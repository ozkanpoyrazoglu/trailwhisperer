# TrailWhisperer Local

Investigate AWS CloudTrail and VPC Flow Logs in plain English from **Claude Code** or **Claude Desktop**, with no CloudFormation stack and nothing always-on.

Claude writes the Athena SQL. This MCP server decides whether it runs:

| Decision | Made by |
|---|---|
| Turning the question into SQL, explaining the result | Claude |
| Is the SQL safe? (one `SELECT`, whitelisted tables, mandatory `dt` partition filter, max window) | `guardrail.py`, by parsing the SQL with sqlglot, never by string matching |
| How much will it scan? | `estimate.py`, from the real S3 object sizes of the partitions the SQL touches |
| Should it run? | You, in the MCP client's tool-approval prompt |
| Hard ceiling if everything else fails | The Athena workgroup's `BytesScannedCutoffPerQuery` |

The guardrail is the same module the [serverless version](../README.md) uses.

## What you need

- An existing CloudTrail trail delivering to S3 (VPC Flow Logs to S3 optional)
- Python 3.11+ and [uv](https://docs.astral.sh/uv/)
- AWS credentials that can create a Glue database, an Athena workgroup and an S3 bucket (only for `init`)

## 1. Create the Athena side (about 10 seconds)

```bash
uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local init \
  --cloudtrail-bucket my-cloudtrail-bucket \
  --vpc-bucket my-flowlogs-bucket        # optional
```

`init` discovers which accounts and Regions actually have logs, then creates:

- Glue database `trailwhisperer_local` with partition-projected tables `cloudtrail_logs` and `vpc_flow_logs` (no crawler)
- Athena workgroup `trailwhisperer-local` with a 1 GB per-query scan cutoff (`--cutoff-mb`)
- Results bucket `trailwhisperer-local-results-<account>-<region>`, public access blocked, objects expire after 7 days

Use `--cloudtrail-prefix` if your trail writes under a key prefix, and `--org-id o-xxxx` for an organization trail.

## 2. Give the server its own, narrow identity

```bash
uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local policy > tw-policy.json
```

Attach that policy to a role and point an AWS profile at it. The server can then only run queries in its workgroup, read its two tables and the log buckets, and write query results. Add `--kms-key-arn` if your trail is KMS-encrypted.

## 3. Add it to Claude Code

```bash
claude mcp add trailwhisperer -e AWS_PROFILE=trailwhisperer -e AWS_REGION=eu-central-1 -- \
  uvx --from git+https://github.com/ozkanpoyrazoglu/trailwhisperer trailwhisperer-local serve
```

Allow the read-only tools, keep `run_query` behind a prompt, and stop Claude from going around the server with the AWS CLI. In `.claude/settings.json`:

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

### Other MCP clients (Cursor, Claude Desktop, ...)

The server speaks plain MCP over stdio, so any MCP client works and uses its own model; nothing here calls Bedrock. For Cursor, put this in `.cursor/mcp.json` (or `~/.cursor/mcp.json`); Claude Desktop takes the same block in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trailwhisperer": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/ozkanpoyrazoglu/trailwhisperer", "trailwhisperer-local", "serve"],
      "env": { "AWS_PROFILE": "trailwhisperer", "AWS_REGION": "eu-central-1" }
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

> Who changed security groups in the last 7 days, and did any of them open SSH to the internet?

Claude reads the schema once, writes SQL, calls `check_query`, then asks to run it. `run_query` takes the estimate as an argument and the server checks it against its own, so the approval prompt shows the SQL **and** how many MB it will scan.

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
| `TW_MAX_DAYS` | `30` | widest `dt` window the guardrail accepts |
| `TW_MAX_SCAN_BYTES` | `1073741824` | queries estimated above this are refused before they start |
| `TW_MAX_ROWS` | `200` | rows returned to the model per query |
| `TW_QUERY_TIMEOUT` | `90` | seconds `run_query` waits before handing back an execution id |

Pointing `TW_*` at the tables the serverless stack created also works.
