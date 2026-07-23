# Deploying TrailWhisperer

TrailWhisperer ships **two deployment paths**. Pick one:

| | **Serverless** (`serverless/`) | **EC2** (`ec2/`) |
|---|---|---|
| Compute | API Gateway + Lambda + CloudFront | One EC2 VM running `docker compose` |
| Tooling | Raw CloudFormation, one-click | AWS CDK (Python) |
| Idle cost | **~$0** (pay-per-use, nothing runs idle) | **Not zero** — the VM bills while running (~$15–20/mo for `t3.small` on-demand) |
| Best for | Ephemeral, spin-up-and-tear-down investigations | A long-lived internal box, air-gapped-ish VPCs, or when you'd rather run the same Docker image as local dev |
| TLS / CDN | HTTPS via CloudFront | Plain HTTP on `:8080`/`:8000` (put it behind your own ALB/reverse proxy for TLS) |

Both provision the **same data plane** — an Athena Workgroup with a bytes-scanned
cutoff, a Glue database with partition-projected CloudTrail + VPC Flow Log tables,
an Athena results bucket (7-day lifecycle), a DynamoDB chat-sessions table, an
auto-generated auth-token secret, and a least-privilege IAM role/policy. They differ
only in how the application itself is served.

> **Prerequisites (both paths)**
> - An existing **CloudTrail → S3** setup (management events delivered to a bucket). Optionally a **VPC Flow Logs → S3** bucket (default fields, delivered to S3).
> - **Amazon Bedrock model access** enabled in your deploy region for the model you intend to use.
> - Deploy in the **same region** as your Athena/Glue and Bedrock model access.

---

## Option 1 — Serverless (CloudFormation)

The `serverless/` directory holds `investigator-stack.yaml` (the whole system as one
template) and `scripts/` (build + publish helpers). Deployment is **one click**: the
stack pulls the packaged backend from a release bucket, and a bundled custom resource
publishes the SPA (with the live API URL baked into `config.js`) into S3.

### A. One-click "Launch Stack" (Console)

Once a release is published, `scripts/publish.sh` prints a **Launch Stack URL** per
region. Clicking it opens the CloudFormation console with the template pre-loaded. Then:

1. Fill in the **Parameters** (table below) — at minimum `CloudTrailLogBucketName` and `VpcFlowLogsBucketName`.
2. Check **"I acknowledge that AWS CloudFormation might create IAM resources."**
3. **Create stack** and wait for **CREATE_COMPLETE**.
4. Open the **Outputs** tab → click `UiUrl`. That's the working console.

### B. Deploy via the CLI

```bash
aws cloudformation deploy \
  --template-file serverless/investigator-stack.yaml \
  --stack-name ct-nl-investigator \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    CloudTrailLogBucketName=my-org-cloudtrail-logs \
    VpcFlowLogsBucketName=my-org-vpc-flow-logs \
    ArtifactVersion=v1 \
    ArtifactBucketPrefix=trailwhisperer-artifacts-<account-id> \
    BedrockModelId=anthropic.claude-3-5-sonnet-20241022-v2:0
```

> `ArtifactBucketPrefix` must match the prefix `publish.sh` printed (it appends a
> uniqueness suffix — the AWS account id by default). The one-click Launch URL sets
> this automatically; only the CLI path needs it passed explicitly.

**Parameters:**

| Parameter | Default | Description |
|---|---|---|
| `CloudTrailLogBucketName` | *(required)* | Existing S3 bucket receiving CloudTrail management events. |
| `VpcFlowLogsBucketName` | *(required)* | Existing S3 bucket receiving VPC Flow Logs (default fields). |
| `ArtifactBucketPrefix` | `trailwhisperer-artifacts` | Release bucket prefix; real bucket is `<prefix>-<region>`. `publish.sh` appends a uniqueness suffix (AWS account id by default), so use the prefix it prints, e.g. `trailwhisperer-artifacts-<account-id>`. |
| `ArtifactVersion` | `v1` | Release version = S3 key prefix under the artifact bucket. |
| `GlueDatabaseName` | `trailwhisperer_db` | Glue database created by the stack. |
| `GlueTableName` | `cloudtrail_logs` | CloudTrail Glue table name. |
| `VpcFlowLogsTableName` | `vpc_flow_logs` | VPC Flow Logs Glue table name. |
| `BedrockModelId` | `anthropic.claude-3-5-sonnet-20241022-v2:0` | Bedrock model for NL→SQL and summarization. |
| `BytesScannedCutoff` | `1073741824` (1 GB) | Per-query bytes-scanned cap (runaway-cost guard). |
| `AllowedTimeRangeMaxDays` | `90` | Max time window (days) the orchestrator allows per query. |
| `EnableProwlerScan` | `false` | Provision the optional Prowler security scan (CodeBuild + findings bucket + Glue table). |
| `ProwlerFindingsTableName` | `prowler_findings` | Glue table mapping the Prowler JSON findings (only when `EnableProwlerScan=true`). |

### After it's up

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

Open `UiUrl`, paste the token into the login modal. The API endpoint is already wired
via `config.js` — nothing else to configure.

### Publishing a release (maintainers)

The Launch Stack button needs the packaged artifacts hosted in a regional bucket.
Publish once per version, per region you want to support:

```bash
# builds dist/backend.zip (manylinux wheels) and uploads backend + stack + frontend
serverless/scripts/publish.sh v1 us-east-1 eu-west-1
```

This runs `serverless/scripts/build-backend.sh` (packages `backend/` + deps into a
Python 3.13 Lambda zip via manylinux wheels — works on macOS/Linux, no Docker), then
for each region creates `trailwhisperer-artifacts-<account-id>-<region>` if missing
and uploads `backend.zip`, `stack.yaml`, and `frontend/`. It prints the
`ArtifactBucketPrefix` to use plus a ready-to-use **Launch Stack URL** (which already
embeds that prefix).

- **Backend arch:** set `LAMBDA_ARCH=aarch64` before building for arm64 Lambdas (default `x86_64`).
- **Bucket prefix:** override the base with `ARTIFACT_BUCKET_PREFIX=...`. S3 names are global,
  so the script appends a uniqueness suffix — the **AWS account id** by default (stable across
  re-publishes, so the bucket is reused). Override the suffix with `ARTIFACT_BUCKET_SUFFIX=...`
  (e.g. a timestamp). For a CLI deploy, pass the printed prefix as the `ArtifactBucketPrefix` param.

> **⚠️ Public distribution — security note.** By default the artifact bucket is
> **private**, so only principals in the bucket's own AWS account can deploy from it.
> To let *anyone* deploy from a public Launch Stack link, run `PUBLIC=1 serverless/scripts/publish.sh ...`
> to make the release objects world-readable. Never put secrets in the artifact bucket.

### Teardown

```bash
aws cloudformation delete-stack --stack-name ct-nl-investigator
```

The SPA-deployer custom resource empties the stack-owned S3 buckets on delete, so this
is genuinely one command. It does not touch your source CloudTrail/VPC log buckets or
the release bucket.

---

## Option 2 — EC2 (AWS CDK, Python)

The `ec2/` directory is a CDK app that provisions the shared data plane **plus** a single
EC2 instance. The instance's UserData installs Docker + Compose, clones this repo,
writes the `.env` and the SPA's `config.js` from the stack's own resources, then runs
`docker compose up` — the same containers you run in local dev, on a VM.

Choose this when you want a long-lived box rather than the ephemeral serverless stack.
**It is not zero-idle-cost:** the VM bills while it is running. It keeps the project's
other cost constraints, though — the VPC has **no NAT gateway** (the instance sits in a
public subnet behind a security group), and Athena still enforces the bytes-scanned cutoff.

### How the instance reaches AWS

boto3 inside the containers resolves credentials from the **instance role via IMDS** —
no AWS keys are ever written to disk. The instance metadata hop limit is set to `2` so
containers on Docker's bridge network can reach IMDSv2. SSM Session Manager is enabled,
so you can shell in without an SSH key:

```bash
aws ssm start-session --target <InstanceId-from-outputs>
```

### Prerequisites

- **Node.js** (for the CDK CLI) and **Python 3.9+**.
- The **AWS CDK CLI**: `npm install -g aws-cdk`.
- CDK **bootstrapped** in the target account/region: `cdk bootstrap aws://<account>/<region>`.
- The `RepoUrl` must be **reachable from the instance** (a public GitHub URL by default). For a private repo, bake credentials into UserData or pre-build an AMI instead.

### Deploy

```bash
cd deploy/ec2
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cdk deploy \
  --parameters CloudTrailLogBucketName=my-org-cloudtrail-logs \
  --parameters VpcFlowLogsBucketName=my-org-vpc-flow-logs \
  --parameters AllowedIngressCidr=203.0.113.10/32 \
  --parameters BedrockModelId=anthropic.claude-3-5-sonnet-20241022-v2:0
```

**Parameters** (in addition to the data-plane ones shared with the serverless stack —
`GlueDatabaseName`, `GlueTableName`, `VpcFlowLogsTableName`, `BedrockModelId`,
`BytesScannedCutoff`, `AllowedTimeRangeMaxDays`):

| Parameter | Default | Description |
|---|---|---|
| `CloudTrailLogBucketName` | *(required)* | Existing CloudTrail log bucket. |
| `VpcFlowLogsBucketName` | *(required)* | Existing VPC Flow Logs bucket. |
| `InstanceType` | `t3.small` | EC2 instance type for the app VM. |
| `RepoUrl` | `https://github.com/ozkanpoyrazoglu/trailwhisperer.git` | Git URL the instance clones the app from. |
| `RepoBranch` | `main` | Branch to check out. |
| `AllowedIngressCidr` | `0.0.0.0/0` | CIDR allowed to reach ports 8080/8000. **Lock this to your IP** — the default is open to the internet. |

### After it's up

First boot takes a few minutes (Docker install, image build, `docker compose up`). Then:

```bash
# UI URL (http://<public-ip>:8080) and instance id
aws cloudformation describe-stacks --stack-name TrailWhispererEc2Stack \
  --query "Stacks[0].Outputs" --output table

# Auth token (paste into the login modal)
aws secretsmanager get-secret-value \
  --secret-id "$(aws cloudformation describe-stacks --stack-name TrailWhispererEc2Stack \
    --query "Stacks[0].Outputs[?OutputKey=='AuthSecretArn'].OutputValue" --output text)" \
  --query SecretString --output text | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])"
```

Open `UiUrl`, paste the token. The SPA is already wired to the instance's backend via
the `config.js` written at boot.

> **HTTP only.** This path serves plain HTTP. For anything beyond a trusted network,
> keep `AllowedIngressCidr` locked down and/or front the instance with your own ALB +
> ACM certificate (or a reverse proxy) for TLS.

### Troubleshooting first boot

UserData logs land in `/var/log/cloud-init-output.log`. Shell in via SSM and check:

```bash
sudo tail -n 100 /var/log/cloud-init-output.log
cd /opt/trailwhisperer && sudo docker compose ps && sudo docker compose logs --tail=50
```

### Teardown

```bash
cd deploy/ec2 && cdk destroy
```

The results bucket and sessions table are created with a destroy removal policy (and the
results bucket auto-empties), so teardown is clean. Your source log buckets are external
inputs and are never touched.
