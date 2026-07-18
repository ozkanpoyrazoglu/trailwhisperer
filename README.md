# TrailWhisperer

**Natural-language forensic auditing for AWS CloudTrail & VPC Flow Logs.**

Ask *"Who changed the security group last week?"* or *"Show me rejected SSH connections to internal hosts yesterday."* TrailWhisperer translates the question into Athena SQL with Amazon Bedrock (Claude), shows you the query for approval, runs it, and summarizes the returned rows into a plain-language narrative with security flags.

It is **serverless, ephemeral, and low-cost**: there is no always-on compute. Deploy it when you need to investigate, tear it down when you're done. Idle cost is effectively zero.

---

## What it does (step by step)

1. **You ask a question in natural language** in the web console (optionally scoping it with a time range or model choice).
2. **Grounded NL → SQL.** The backend sends your question to Amazon Bedrock along with the Glue table schema, a CloudTrail/VPC field crib-sheet, and few-shot examples. Bedrock returns Athena (Trino-dialect) SQL.
3. **Guardrail validation.** The generated SQL is parsed (not string-matched) and rejected unless it is a single **`SELECT`** against a whitelisted table, with a **mandatory `dt` partition filter** and a bounded time window. This keeps the query read-only *and* keeps Athena bytes-scanned (cost) low.
4. **Human-in-the-loop approval.** The SQL is **never executed automatically.** It is displayed in an approval "warrant" modal — with a plain-language explanation of what it does and an estimated scan scope — for you to **Approve / Edit / Cancel**. (An opt-in auto-run mode still shows the SQL and offers a cancellable countdown before running.)
5. **Athena execution.** On approval, the query runs against your CloudTrail / VPC Flow Log data via an Athena Workgroup that enforces a per-query bytes-scanned cutoff.
6. **Grounded summarization.** Bedrock summarizes **only the rows Athena actually returned** — it does not invent data — into a narrative plus heuristic severity flags (info / review / critical). Results are also shown as a paginated table with a per-query bytes-scanned and estimated-cost indicator.
7. **In-session case log.** Every investigation this session is logged in the sidebar so you can jump back to or re-run earlier questions.

If an Athena query fails, the error and the bad SQL are fed back to the model to self-correct (a couple of rounds), then you're offered a manual edit.

## What it's useful for

- **Incident response & forensic auditing** without learning Athena SQL or the CloudTrail JSON schema.
- **Security investigations** across two log sources — CloudTrail (*who did what*) and VPC Flow Logs (*network traffic*) — including **cross-log correlation** (e.g. "did this IP make API calls *and* network connections?") via `UNION ALL`.
- **Inspecting complex nested JSON** such as security-group `ipPermissions` to catch things like SSH/RDP opened to `0.0.0.0/0`.
- **Ad-hoc, on-demand auditing** where standing up a full SIEM is overkill — spin it up, investigate, tear it down.

## Architecture

```
Static SPA (S3 + CloudFront)
        │
        ▼
API Gateway (HTTP API)  →  Lambda (FastAPI + Mangum, Python 3.13)
                               ├─ bedrock:InvokeModel      → Bedrock (Claude): NL→SQL + summarize
                               ├─ athena:StartQueryExecution → Athena Workgroup → Glue Catalog → S3 logs (read-only)
                               └─ returns generated SQL + summary → SPA
```

- **Frontend:** Vanilla JS / HTML / CSS SPA — no build step, hosted on S3 behind CloudFront.
- **Backend:** One Python Lambda running FastAPI via the Mangum adapter. Three endpoints: `POST /api/generate-sql`, `POST /api/execute-sql`, `GET /api/results/{execution_id}`.
- **Data catalog:** Glue tables use **partition projection** (`account` / `region` / `dt`) — no Glue Crawler, no always-on cost.
- **Auth:** A single API key auto-generated into AWS Secrets Manager at deploy time; the SPA sends it as a bearer token.

### Design constraints (non-negotiable)

- **Read-only, `SELECT`-only** — enforced by SQL parsing, against a table whitelist.
- **Human-in-the-loop** — generated SQL is always shown and requires explicit approval; never auto-executed silently.
- **Mandatory partition/time filter** — every query must prune on `dt` and bound its time window (capped by `AllowedTimeRangeMaxDays`).
- **Grounding over hallucination** — summaries derive strictly from returned rows.
- **Least-privilege IAM** — Bedrock scoped to the chosen model, Athena to the workgroup, Glue to the DB/tables, S3 read-only on the log buckets.

---

## Deploying to AWS

### Prerequisites

- An **existing CloudTrail → S3** setup (management events delivered to a bucket). Optionally a **VPC Flow Logs → S3** bucket (default fields, delivered to S3).
- **Amazon Bedrock model access** enabled in your region for the model you intend to use (default: `anthropic.claude-3-5-sonnet-20241022-v2:0`). Enable it in the Bedrock console under *Model access*.
- AWS CLI configured with permissions to create the stack (`--capabilities CAPABILITY_IAM`).

> **Region note:** deploy in the **same region** as your Athena/Glue and Bedrock model access.

### 1. Deploy the CloudFormation stack

The whole system is one importable template: `investigator-stack.yaml`.

```bash
aws cloudformation deploy \
  --template-file investigator-stack.yaml \
  --stack-name ct-nl-investigator \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    CloudTrailLogBucketName=my-org-cloudtrail-logs \
    VpcFlowLogsBucketName=my-org-vpc-flow-logs \
    BedrockModelId=anthropic.claude-3-5-sonnet-20241022-v2:0
```

**Parameters:**

| Parameter | Default | Description |
|---|---|---|
| `CloudTrailLogBucketName` | *(required)* | Existing S3 bucket receiving CloudTrail management events. |
| `VpcFlowLogsBucketName` | *(required)* | Existing S3 bucket receiving VPC Flow Logs (default fields). |
| `GlueDatabaseName` | `trailwhisperer_db` | Glue database created by the stack. |
| `GlueTableName` | `cloudtrail_logs` | CloudTrail Glue table name. |
| `VpcFlowLogsTableName` | `vpc_flow_logs` | VPC Flow Logs Glue table name. |
| `BedrockModelId` | `anthropic.claude-3-5-sonnet-20241022-v2:0` | Bedrock model for NL→SQL and summarization. |
| `BytesScannedCutoff` | `1073741824` (1 GB) | Per-query bytes-scanned cap (runaway-cost guard). |
| `AllowedTimeRangeMaxDays` | `90` | Max time window (days) the orchestrator allows per query. |

The stack creates: the Athena results bucket (7-day lifecycle) and SPA bucket, a CloudFront distribution (Origin Access Control), the Athena Workgroup with the bytes-scanned cutoff, the Glue database + two partition-projected tables, the auth-token secret (auto-generated), the Lambda + HTTP API, and a least-privilege IAM role.

### 2. Read the stack outputs

```bash
aws cloudformation describe-stacks --stack-name ct-nl-investigator \
  --query 'Stacks[0].Outputs' --output table
```

| Output | Use |
|---|---|
| `UiUrl` | CloudFront URL of the web console. |
| `ApiUrl` | HTTP API endpoint the SPA calls. |
| `SpaBucketName` | S3 bucket to upload the frontend into. |
| `AuthSecretArn` | Secrets Manager ARN holding the API token (log in with its value). |
| `AthenaWorkGroupName` | The Athena Workgroup enforcing the cost cutoff. |

### 3. Upload the frontend

The Lambda ships a placeholder handler; upload the SPA to the `SpaBucketName` bucket:

```bash
aws s3 sync ./frontend "s3://$(aws cloudformation describe-stacks \
  --stack-name ct-nl-investigator \
  --query "Stacks[0].Outputs[?OutputKey=='SpaBucketName'].OutputValue" --output text)/"
```

### 4. Retrieve your auth token

```bash
aws secretsmanager get-secret-value \
  --secret-id "$(aws cloudformation describe-stacks --stack-name ct-nl-investigator \
    --query "Stacks[0].Outputs[?OutputKey=='AuthSecretArn'].OutputValue" --output text)" \
  --query SecretString --output text
```

### 5. Open the console

Browse to the `UiUrl`. On first load, paste the token from step 4 into the login modal (stored in `localStorage`, sent as `Authorization: Bearer <token>`). The SPA reads the backend base URL from an `?api=<ApiUrl>` query parameter (defaulting to `http://localhost:8000` for local dev) — point it at your `ApiUrl`.

### Teardown

Everything is one stack, so cleanup is one command (empty the S3 buckets first if they contain objects):

```bash
aws cloudformation delete-stack --stack-name ct-nl-investigator
```

---

## Local development

A `docker-compose.yml` runs the FastAPI backend (Uvicorn auto-reload) and a static file server for the frontend.

### 1. Configure environment

```bash
cp .env.example .env
```

The defaults work out of the box. The backend calls Bedrock/Athena through `boto3`, which resolves AWS credentials from the standard provider chain:

- **Host `~/.aws` profile:** leave the AWS vars in `.env` commented out.
- **No mounted profile (plain VM):** set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and (for temporary/STS/SSO creds) `AWS_SESSION_TOKEN` in `.env`.

See `AUTHENTICATION.md` for details. Keep `.env` out of version control.

> **Athena locally:** running against real Athena requires `ATHENA_OUTPUT_LOCATION` to be set when using the default `primary` workgroup (which has no results location). Match `AWS_REGION` to where your Glue tables live.
>
> After editing `.env`, recreate the container (env changes need a rebuild, not just a restart): `docker compose up -d --force-recreate`.

### 2. Run

```bash
docker compose up --build
```

- **Backend health:** http://localhost:8000/api/health
- **Frontend:** http://localhost:8080

The default local auth token is `local-dev-token` (from `docker-compose.yml`); use it in the login modal.

---

## Repository layout

```
backend/                  FastAPI app (main.py), Dockerfile, requirements, mock_server.py
frontend/                 Vanilla JS SPA (index.html, style.css, app.js) — no build step
investigator-stack.yaml   One-click CloudFormation template (the whole system)
docker-compose.yml        Local dev: backend (Uvicorn) + static frontend
AGENT_CONTEXT.md          Canonical architecture summary
AUTHENTICATION.md         Backend AWS credential resolution (Lambda vs. local)
SECURITY_FINDINGS.md      Security review notes
roadmap.md                Development tracker
```
