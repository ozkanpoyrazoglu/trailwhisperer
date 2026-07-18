# Backend AWS Authentication

The backend calls Bedrock and Athena through `boto3`, which resolves AWS
credentials automatically from its default provider chain. This means the same
code works in both deployment targets with no changes — only *where* the
credentials come from differs.

## 1. AWS Environment (CloudFormation / Lambda)

When deployed via `investigator-stack.yaml`, the Lambda runs under the
least-privilege **IAM execution role** provisioned by the stack. AWS injects
temporary role credentials into the runtime, and `boto3` picks them up
automatically.

- No access keys are stored, passed, or rotated by hand.
- Nothing to configure — this is the default in the AWS environment.

## 2. Local / VM Environment (Docker)

For local development or a plain VM without a mounted `~/.aws` profile, supply
credentials through the `.env` file. `docker-compose.yml` loads `.env`
(`env_file`) into the container, and `boto3` detects the standard variables.

Set these in `.env` (see `.env.example`):

```
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...      # only for temporary (STS/SSO) credentials
```

Notes:

- If your host already has a working `~/.aws` profile, leave these commented
  out and rely on the profile instead — do not set both.
- `AWS_SESSION_TOKEN` is required only when using temporary credentials
  (STS, SSO, assumed roles). Long-lived IAM user keys don't need it.
- `.env` holds secrets — keep it out of version control.
