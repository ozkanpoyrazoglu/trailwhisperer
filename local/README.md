# TrailWhisperer Local

Investigate AWS CloudTrail and VPC Flow Logs in plain English from the AI agent you already use (**Claude Code**, **Cursor**, **Claude Desktop** or any other MCP client), with no CloudFormation stack, nothing always-on and no Bedrock bill.

Your agent writes the Athena SQL. This MCP server decides whether it runs:

| Decision | Made by |
|---|---|
| Turning the question into SQL, explaining the result | Your agent's model |
| Is the SQL safe? | `guardrail.py`, by parsing the SQL with sqlglot, never by string matching |
| How much will it scan? | `estimate.py`, from the real S3 object sizes of the partitions the SQL touches |
| Can't be sized? | It doesn't run (fail closed) |
| Should it run? | You, in the MCP client's tool-approval prompt |
| Hard ceiling if everything else fails | The Athena workgroup's `BytesScannedCutoffPerQuery` |

The guardrail is the same module the [serverless version](../README.md) uses, so a fix lands in both.

## Why local

- **Nothing to deploy into the account you investigate.** `init` creates four objects (a Glue database with two tables, an Athena workgroup, a results bucket) that cost nothing when idle. The serverless stack is about 30 resources.
- **The model is the expensive part, and you already pay for it.** In live tests, an investigation used $0.21 to $0.58 of model time, while Athena charged $0.00005 to $0.0004. Locally, that model time comes out of your agent subscription instead of a per-question Bedrock bill.
- **One question can span both log sources.** CloudTrail (who did what) and VPC Flow Logs (what connected where) are correlated with `UNION ALL`, for example "did any IP that was rejected at the network also make API calls?"

## What you need

- An existing CloudTrail trail delivering to S3 (VPC Flow Logs to S3 optional)
- Python 3.11+ and [uv](https://docs.astral.sh/uv/)
- AWS credentials that can create a Glue database, an Athena workgroup and an S3 bucket (only for `init`)

## 1. Create the Athena side (about 10 seconds)

Run it in the Region of your log bucket. Athena can read a bucket in another Region, but you pay for the cross-Region transfer.

```bash
AWS_REGION=us-east-1 uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local init \
  --cloudtrail-bucket my-cloudtrail-bucket \
  --vpc-bucket my-flowlogs-bucket        # optional
```

`init` discovers which accounts and Regions actually have logs, so queries and the estimator never visit empty prefixes. Then it creates:

- Glue database `trailwhisperer_local` with partition-projected tables `cloudtrail_logs` and `vpc_flow_logs` (no crawler)
- Athena workgroup `trailwhisperer-local` with a 1 GB per-query scan cutoff (`--cutoff-mb`), enforced so clients can't override it
- Results bucket `trailwhisperer-local-results-<account>-<region>`, public access blocked, objects expire after 7 days

Use `--cloudtrail-prefix` if your trail writes under a key prefix, and `--org-id o-xxxx` for an organization trail.

Check the setup:

```bash
AWS_REGION=us-east-1 uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local doctor
```

```
  ok    Glue tables: cloudtrail_logs, vpc_flow_logs
  ok    Athena workgroup: trailwhisperer-local, cutoff 1024 MB, enforced=True
  ok    1-day scan estimate for cloudtrail_logs: 1.70 MB in 1243 objects across 34 prefixes
```

## 2. Give the server its own, narrow identity

```bash
uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local policy > tw-policy.json
```

Attach that policy to a role and point an AWS profile at it. The server can then only run queries in its workgroup, read its two tables and the log buckets, and write query results. Add `--kms-key-arn` if your trail is KMS-encrypted.

## 3. Add it to your agent

### Claude Code

```bash
claude mcp add trailwhisperer -e AWS_PROFILE=trailwhisperer -e AWS_REGION=us-east-1 -- \
  uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local serve
```

Allow the read-only tools, keep `run_query` behind a prompt, and stop the agent from going around the server with the AWS CLI. In `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": [
      "mcp__trailwhisperer__get_investigation_context",
      "mcp__trailwhisperer__check_query",
      "mcp__trailwhisperer__get_results"
    ],
    "deny": ["Bash(aws athena:*)", "Bash(aws s3:*)"]
  }
}
```

> **Auto mode skips the prompt.** If Claude Code is in auto mode (shown in the status bar; `Shift+Tab` cycles modes), tool calls are approved without asking, including `run_query`. Switch to the default mode when you want to approve each query. The server-side limits apply either way.

### Cursor, Claude Desktop and other MCP clients

The server speaks plain MCP over stdio, so any MCP client works and uses its own model; nothing here calls Bedrock. For Cursor, put this in `.cursor/mcp.json` (or `~/.cursor/mcp.json`); Claude Desktop takes the same block in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trailwhisperer": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/ozkanpoyrazoglu/trailwhisperer", "trailwhisperer-local", "serve"],
      "env": { "AWS_PROFILE": "trailwhisperer", "AWS_REGION": "us-east-1" }
    }
  }
}
```

Whatever the client, keep `run_query` out of its auto-run / auto-approve list so a person approves each execution.

### Many accounts

Add one entry per account, each with its own profile. The model can't switch accounts, because the profile is fixed in the client config, not passed as a tool argument:

```bash
claude mcp add tw-customer-a -e AWS_PROFILE=customer-a-readonly -e AWS_REGION=eu-central-1 -- uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local serve
claude mcp add tw-customer-b -e AWS_PROFILE=customer-b-readonly -e AWS_REGION=eu-west-1    -- uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local serve
```

## 4. Ask

> Who made security group or IAM changes in the last 30 days? Flag anything risky.

The agent reads the schema once (`get_investigation_context`), writes SQL, calls `check_query`, then asks to run it. `run_query` takes the estimate as an argument and the server checks it against its own, so the approval prompt shows the SQL **and** how many MB it will scan. The answer is built only from the rows that came back, with identities, ARNs and IPs reported verbatim.

## What the guardrail enforces

Every rule is checked on the parsed statement, in `check_query` and again in `run_query`:

- exactly one statement, and it is a `SELECT` or `UNION`
- only the whitelisted tables, only in the configured database (CTE names excluded)
- every `SELECT` that reads a log table filters the `dt` partition in its own `WHERE`, in plain AND context (not under `OR` or `NOT`, not only in a subquery)
- a `dt` bound has one of two shapes: a zero-padded `'yyyy/MM/dd'` literal, or `date_format(current_timestamp - interval 'N' day, '%Y/%m/%d')`; anything else is rejected
- a qualified `dt` must name the log table (an alias hides the table name, as in Trino)
- no JOINs on log tables (correlate with `UNION ALL`); `CROSS JOIN UNNEST` is allowed, but its aliases can't reuse `dt`, `region`, `account` or the table's name
- no window reaches further back than `TW_MAX_DAYS`
- queries estimated above `TW_MAX_SCAN_BYTES`, or that can't be estimated, don't start

Each rule has regression tests in `backend/test_guardrail.py` and `local/tests/`.

## How accurate is the estimate?

CloudTrail and VPC Flow Logs are gzipped row formats, so Athena reads every object in the partitions a query selects and bills those bytes. Summing the S3 object sizes gives the same number. Measured on a test account (17 Regions, one quiet month):

| Query | Partitions | Estimated | Athena scanned |
|---|---|---|---|
| Security group changes, 7 days | 8 days × 17 Regions | 7.08 MB | 7.09 MB |
| Console logins, 30 days | 31 days × 17 Regions | 28.04 MB | 28.04 MB |
| Top API calls, 7 days, `region = 'us-east-1'` | 8 days × 1 Region | 3.32 MB | 3.32 MB |
| Rejected flows by port, one week | 8 days × 1 Region | 13.60 MB | 13.60 MB |

The 0.01 MB difference is a CloudTrail file delivered between the estimate and the run.

## Check and clean up

```bash
trailwhisperer-local doctor     # identity, tables, workgroup cutoff, 1-day scan estimate
trailwhisperer-local teardown   # deletes only what init created; your log buckets are never touched
```

## Settings (environment variables)

| Variable | Default | |
|---|---|---|
| `AWS_PROFILE`, `AWS_REGION` | | identity and Region of the Glue/Athena resources |
| `TW_DATABASE` | `trailwhisperer_local` | |
| `TW_CLOUDTRAIL_TABLE` / `TW_VPC_TABLE` | `cloudtrail_logs` / `vpc_flow_logs` | |
| `TW_WORKGROUP` | `trailwhisperer-local` | |
| `TW_MAX_DAYS` | `30` | widest `dt` window the guardrail accepts; raise it to reach older data |
| `TW_MAX_SCAN_BYTES` | `1073741824` | queries estimated above this are refused before they start |
| `TW_MAX_ROWS` | `200` | rows returned to the model per query |
| `TW_QUERY_TIMEOUT` | `90` | seconds `run_query` waits before handing back an execution id |

Pointing `TW_*` at the tables the serverless stack created also works.

## Limits

- **The guardrail only governs its own path.** An agent uses every tool it has. In testing, Claude Code also checked the account's current state with other AWS tooling in the session. Give the server a narrow profile, deny the AWS CLI paths you don't want the agent to use, and be deliberate about which other AWS tools are installed.
- **VPC Flow Logs format.** The table assumes the default delivery: the 14-field version 2 text format, gzipped, under `AWSLogs/<account>/vpcflowlogs/<region>/yyyy/MM/dd/`. Flow logs with a custom field list, Parquet output or Hive-compatible S3 prefixes need a different table definition and aren't supported yet.
- **Parquet in general.** The estimate is exact for gzipped row formats. For columnar tables Athena reads only some columns, so the estimate would be an upper bound.
- **Organization trails** work with `--org-id`, but every account becomes a prefix to list. Filter by `account` or narrow the window; estimates above 3,000 prefixes are refused.
- **Prowler findings** are only in the serverless version for now.
- **Read access is read access.** The guardrail checks the SQL's shape, not your data. Anyone with the server's profile can read every event in the allowed window, so treat that profile like read access to your audit logs.
