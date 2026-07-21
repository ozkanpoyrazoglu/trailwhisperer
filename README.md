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
- **Correlating static security posture with live activity** — an optional [Prowler scan](#optional-prowler-security-scan) exposes findings (open security groups, failing checks) as a third queryable table, so you can ask *"list my critical Prowler findings"* or line an open-SG finding up against actual VPC traffic on the same port.
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
- **Mandatory partition/time filter** — every query against a **log table** must prune on `dt` and bound its time window (capped by `AllowedTimeRangeMaxDays`). The optional Prowler findings table is exempt (it's a static snapshot, not time-partitioned).
- **Grounding over hallucination** — summaries derive strictly from returned rows.
- **Least-privilege IAM** — Bedrock scoped to the chosen model, Athena to the workgroup, Glue to the DB/tables, S3 read-only on the log buckets.

---

## Cost

TrailWhisperer is built to cost **almost nothing when idle** and only a few cents per investigation when used. There is no always-on compute (no NAT gateway, EC2, Redshift, Glue Crawler, or OpenSearch), so a deployed-but-unused stack drifts toward zero.

> ⚠️ **These are rough, order-of-magnitude estimates** (us-east-1, early 2026) to set expectations — **not** a billing guarantee. Actual charges depend on your region, the Bedrock model you pick, how much data Athena scans, and how often you query. Always confirm against the [AWS pricing pages](https://aws.amazon.com/pricing/) and your own Cost Explorer.

### Idle cost (deployed, no queries)

| Resource | Idle charge |
|---|---|
| Lambda, API Gateway, Athena, Bedrock | **$0** — pay-per-use, nothing runs when idle |
| DynamoDB (`PAY_PER_REQUEST` sessions table) | **$0** idle; rows auto-expire via TTL |
| Glue Data Catalog (partition projection, no crawler) | **$0** (free under 1M objects) |
| Secrets Manager (auth token) | **~$0.40 / month** per secret |
| S3 (SPA + Athena results w/ 7-day lifecycle) | **pennies / month** (tiny objects, results expire) |
| CloudFront | **~$0** idle (pay per request/GB served) |

**Idle total: well under ~$1/month**, dominated by the one Secrets Manager secret.

### Per-investigation cost

Each question makes up to 3 Bedrock calls (generate SQL → plain-language explanation → summarize) plus one Athena query:

- **Athena** — **$5 per TB scanned**, and the workgroup enforces a `BytesScannedCutoff` (default **1 GB → ≤ $0.005/query** hard cap). The mandatory `dt` partition pruning keeps typical queries far below that, so most investigations cost a **fraction of a cent** in Athena.
- **Bedrock** — priced per token; the grounded system prompt (~8K tokens) is re-sent on each generation (no prompt caching yet). Rough cost per investigation by model:

  | Bedrock model | Approx. $/1M in / out | ~Per investigation |
  |---|---|---|
  | Claude 3.5 Sonnet v2 *(default)* | ~$3 / ~$15 | **~$0.03–0.08** |
  | Claude 3.5 Haiku / Nova Lite | ~$0.80–1 / ~$4–5 | **~$0.01–0.02** |
  | Amazon Nova Micro | ~$0.035 / ~$0.14 | **sub-cent** |

  Switch models in the composer's model picker to trade cost for quality. (Bedrock token prices are set by AWS and vary by model/region — check the [Bedrock pricing page](https://aws.amazon.com/bedrock/pricing/).)

**Rule of thumb:** a day of active investigating on the default model is typically **cents to low single-digit dollars**.

### Optional Prowler scan cost

If you enable `EnableProwlerScan` (see below), a scan runs on **CodeBuild** (`BUILD_GENERAL1_SMALL`, ~$0.005/build-minute). A full 15–45 min account scan is **~$0.08–0.25 per run**, plus negligible S3 storage for the JSON findings. It only runs when you trigger it, so it adds nothing to idle cost.

---

## Deploying to AWS

Deployment is **one click**: the CloudFormation stack pulls the packaged backend from a release bucket, and a bundled custom resource publishes the SPA (with the live API URL baked into `config.js`) into S3 — no manual Lambda upload, no manual S3 sync, no `?api=` wiring.

There are two audiences:

- **Deploying an existing release** → just click *Launch Stack* (or run the CLI command). Start here.
- **Publishing a release** (you maintain the artifacts) → see [Publishing a release](#publishing-a-release-maintainers) first, once.

### Prerequisites

- An **existing CloudTrail → S3** setup (management events delivered to a bucket). Optionally a **VPC Flow Logs → S3** bucket (default fields, delivered to S3).
- **Amazon Bedrock model access** enabled in your region for the model you intend to use (default: `anthropic.claude-3-5-sonnet-20241022-v2:0`). Enable it in the Bedrock console under *Model access*.
- A **published release** in the region you're deploying to (an artifact bucket `trailwhisperer-artifacts-<region>` containing `backend.zip` + frontend). If you're the maintainer and haven't published yet, do [that](#publishing-a-release-maintainers) first.

> **Region note:** deploy in the **same region** as your Athena/Glue, Bedrock model access, **and the artifact bucket** (Lambda code buckets are region-local).

### Option A — One-click "Launch Stack" (Console)

Once a release is published, `scripts/publish.sh` prints a **Launch Stack URL** per region. Put it behind a button in your fork's README:

```markdown
[![Launch Stack](https://s3.amazonaws.com/cloudformation-examples/cloudformation-launch-stack.png)](https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://trailwhisperer-artifacts-us-east-1.s3.us-east-1.amazonaws.com/v1/stack.yaml&stackName=ct-nl-investigator&param_ArtifactVersion=v1)
```

Clicking it opens the CloudFormation console with the template pre-loaded. Then:

1. Fill in the **Parameters** (see the table below) — at minimum `CloudTrailLogBucketName` and `VpcFlowLogsBucketName`.
2. Check **"I acknowledge that AWS CloudFormation might create IAM resources."**
3. **Create stack** and wait for **CREATE_COMPLETE**.
4. Open the **Outputs** tab → click `UiUrl`. That's the working console.

### Option B — Deploy via the CLI

```bash
aws cloudformation deploy \
  --template-file investigator-stack.yaml \
  --stack-name ct-nl-investigator \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    CloudTrailLogBucketName=my-org-cloudtrail-logs \
    VpcFlowLogsBucketName=my-org-vpc-flow-logs \
    ArtifactVersion=v1 \
    BedrockModelId=anthropic.claude-3-5-sonnet-20241022-v2:0
```

**Parameters:**

| Parameter | Default | Description |
|---|---|---|
| `CloudTrailLogBucketName` | *(required)* | Existing S3 bucket receiving CloudTrail management events. |
| `VpcFlowLogsBucketName` | *(required)* | Existing S3 bucket receiving VPC Flow Logs (default fields). |
| `ArtifactBucketPrefix` | `trailwhisperer-artifacts` | Release bucket prefix; real bucket is `<prefix>-<region>`. |
| `ArtifactVersion` | `v1` | Release version = S3 key prefix under the artifact bucket. |
| `GlueDatabaseName` | `trailwhisperer_db` | Glue database created by the stack. |
| `GlueTableName` | `cloudtrail_logs` | CloudTrail Glue table name. |
| `VpcFlowLogsTableName` | `vpc_flow_logs` | VPC Flow Logs Glue table name. |
| `BedrockModelId` | `anthropic.claude-3-5-sonnet-20241022-v2:0` | Bedrock model for NL→SQL and summarization. |
| `BytesScannedCutoff` | `1073741824` (1 GB) | Per-query bytes-scanned cap (runaway-cost guard). |
| `AllowedTimeRangeMaxDays` | `90` | Max time window (days) the orchestrator allows per query. |
| `EnableProwlerScan` | `false` | When `true`, provision the optional [Prowler security scan](#optional-prowler-security-scan) (CodeBuild + findings bucket + Glue table) and expose findings to the orchestrator. |
| `ProwlerFindingsTableName` | `prowler_findings` | Glue table mapping the Prowler JSON findings (used only when `EnableProwlerScan=true`). |

The stack creates: the Athena results bucket (7-day lifecycle) and SPA bucket, a CloudFront distribution (Origin Access Control), the Athena Workgroup with the bytes-scanned cutoff, the Glue database + two partition-projected tables, the auth-token secret (auto-generated), the orchestrator Lambda (code from the release bucket) + HTTP API, a least-privilege IAM role, and the SPA-deployer custom resource that publishes the frontend + `config.js`.

### After it's up

Get the URL and login token:

```bash
# Console URL
aws cloudformation describe-stacks --stack-name ct-nl-investigator \
  --query "Stacks[0].Outputs[?OutputKey=='UiUrl'].OutputValue" --output text

# Auth token (paste into the login modal on first load)
aws secretsmanager get-secret-value \
  --secret-id "$(aws cloudformation describe-stacks --stack-name ct-nl-investigator \
    --query "Stacks[0].Outputs[?OutputKey=='AuthSecretArn'].OutputValue" --output text)" \
  --query SecretString --output text
```

Open `UiUrl`, paste the token into the login modal (stored in `localStorage`, sent as `Authorization: Bearer <token>`). The API endpoint is already wired via `config.js` — nothing else to configure.

Other outputs: `ApiUrl` (HTTP API endpoint), `SpaBucketName`, `AthenaWorkGroupName`. When `EnableProwlerScan=true`, also `ProwlerScanProjectName` (the CodeBuild project to trigger) and `ProwlerFindingsBucketName`.

---

## Optional Prowler security scan

Setting `EnableProwlerScan=true` provisions an optional [Prowler](https://github.com/prowler-cloud/prowler) scan so you can query your static security posture alongside the logs. It adds (only when enabled):

- a **CodeBuild project** that runs `prowler aws -M json-asff -B <bucket>` (its role uses the AWS-managed `SecurityAudit` + `ViewOnlyAccess` policies — read-only, account-wide),
- a **findings S3 bucket** for the JSON output, and
- a **Glue table** (default `prowler_findings`) exposing the findings to Athena.

The orchestrator's prompt and guardrail learn the new table automatically (via the `GLUE_PROWLER_TABLE` env var): it is whitelisted for `SELECT`, but — because Prowler findings are a **point-in-time snapshot, not time-series** — it is **exempt from the mandatory `dt` partition filter** the log tables require.

**Running a scan.** The scan is **not** scheduled by default — trigger it manually (or add your own EventBridge rule). CodeBuild runs the scan and writes findings to the bucket; a full account scan can take ~15–45 min:

```bash
aws codebuild start-build --project-name <ProwlerScanProjectName-from-outputs>
```

Once findings land, ask things like *"List my critical Prowler findings"* or *"Which high-severity Prowler checks are failing?"* (sample chips for these are in the console's query library).

> **Correlation caveat — honest scope.** You can also ask *"did the open security groups flagged by Prowler receive any internet traffic?"*, which `UNION ALL`s the finding with VPC Flow Logs. This is a **heuristic, side-by-side correlation by port / internet-facing traffic — not a precise per-security-group join.** VPC Flow Logs record ENIs and IPs and carry **no security-group id**, so there is no key to tie a *specific* `sg-…` to specific flows. Treat it as a triage aid, not proof.

> **Deploy tuning.** The Glue table advertises flat columns (`status`, `severity`, `check_id`, `resource_id`, …); Prowler's ASFF output is nested, so the SerDe field mapping and storage location may need adjusting against a real scan before Athena reads it cleanly (tracked under roadmap Phase 8 / Phase 19).

---

## Publishing a release (maintainers)

The Launch Stack button needs the packaged artifacts hosted in a regional bucket. Publish once per version, per region you want to support:

```bash
# builds dist/backend.zip (manylinux wheels) and uploads backend + stack + frontend
scripts/publish.sh v1 us-east-1 eu-west-1
```

This runs `scripts/build-backend.sh` (packages `backend/` + its deps into a Python 3.13 Lambda zip using manylinux wheels — works on macOS/Linux, no Docker), then for each region creates `trailwhisperer-artifacts-<region>` if missing and uploads `backend.zip`, `stack.yaml`, and `frontend/`. It prints a ready-to-use **Launch Stack URL** for each region.

- **Backend arch:** set `LAMBDA_ARCH=aarch64` before building for arm64 Lambdas (default `x86_64`).
- **Bucket prefix:** override with `ARTIFACT_BUCKET_PREFIX=...` (must match the `ArtifactBucketPrefix` stack parameter).

> **⚠️ Public distribution — security note.** By default the artifact bucket is **private**, so only principals in the bucket's **own AWS account** can deploy from it (fine for your own/org use). To let *anyone* deploy from a public Launch Stack link, run `PUBLIC=1 scripts/publish.sh ...` to make the release objects world-readable. Only do this for artifacts you intend to distribute publicly — the `backend.zip`, template, and frontend become downloadable by anyone. Never put secrets in the artifact bucket.

### Teardown

Everything is one stack, and the SPA-deployer custom resource empties the stack-owned S3 buckets (SPA + Athena results) on delete, so cleanup is genuinely one command:

```bash
aws cloudformation delete-stack --stack-name ct-nl-investigator
```

(This does not touch your source CloudTrail/VPC log buckets or the release/artifact bucket — those are external inputs.)

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
  requirements-lambda.txt   Lambda-only deps (no uvicorn; boto3 from runtime)
frontend/                 Vanilla JS SPA (index.html, style.css, app.js, config.js) — no build step
scripts/build-backend.sh  Package backend/ into dist/backend.zip (manylinux wheels)
scripts/publish.sh        Publish a release to regional artifact buckets + print Launch Stack URL
investigator-stack.yaml   One-click CloudFormation template (the whole system)
docker-compose.yml        Local dev: backend (Uvicorn) + static frontend
AGENT_CONTEXT.md          Canonical architecture summary
AUTHENTICATION.md         Backend AWS credential resolution (Lambda vs. local)
SECURITY_FINDINGS.md      Security review notes
roadmap.md                Development tracker
```
