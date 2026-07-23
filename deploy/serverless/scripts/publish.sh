#!/usr/bin/env bash
# Publish a TrailWhisperer release so the one-click "Launch Stack" button works.
# Uploads backend.zip + stack.yaml + frontend/ to a regional artifact bucket
# ("<prefix>-<region>") for EACH region you want to support.
#
#   deploy/serverless/scripts/publish.sh <version> <region> [region ...]
#   deploy/serverless/scripts/publish.sh v1 us-east-1 eu-west-1
#
# Env:
#   ARTIFACT_BUCKET_PREFIX  bucket prefix (default: trailwhisperer-artifacts)
#   PUBLIC=1                make the release objects world-readable so ANYONE can
#                          deploy from the Launch Stack URL (public distribution).
#                          Default is private = deploy only within the bucket's
#                          own AWS account. See README security note before using.
set -euo pipefail

# Repo root is three levels up: deploy/serverless/scripts/ -> repo root.
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
# The CloudFormation template lives alongside these scripts under deploy/serverless/.
STACK_TEMPLATE="$(cd "$(dirname "$0")/.." && pwd)/investigator-stack.yaml"
VERSION="${1:?usage: publish.sh <version> <region> [region ...]}"; shift
[ "$#" -gt 0 ] || { echo "error: give at least one region" >&2; exit 1; }
PREFIX="${ARTIFACT_BUCKET_PREFIX:-trailwhisperer-artifacts}"
PUBLIC="${PUBLIC:-0}"

"$(dirname "$0")/build-backend.sh"

for region in "$@"; do
  bucket="${PREFIX}-${region}"
  echo "== publishing $VERSION to s3://$bucket ($region) =="

  if ! aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
    echo "   creating bucket"
    if [ "$region" = "us-east-1" ]; then
      aws s3api create-bucket --bucket "$bucket" --region "$region" >/dev/null
    else
      aws s3api create-bucket --bucket "$bucket" --region "$region" \
        --create-bucket-configuration "LocationConstraint=$region" >/dev/null
    fi
  fi

  if [ "$PUBLIC" = "1" ]; then
    echo "   applying PUBLIC read policy"
    aws s3api put-public-access-block --bucket "$bucket" \
      --public-access-block-configuration \
      "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
    aws s3api put-bucket-policy --bucket "$bucket" --policy "{
      \"Version\":\"2012-10-17\",
      \"Statement\":[{\"Sid\":\"PublicRead\",\"Effect\":\"Allow\",\"Principal\":\"*\",
        \"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$bucket/*\"}]}"
  fi

  aws s3 cp "$ROOT/dist/backend.zip"          "s3://$bucket/$VERSION/backend.zip" >/dev/null
  aws s3 cp "$STACK_TEMPLATE"                 "s3://$bucket/$VERSION/stack.yaml"  >/dev/null
  aws s3 sync "$ROOT/frontend/"               "s3://$bucket/$VERSION/frontend/" --delete >/dev/null

  url="https://${bucket}.s3.${region}.amazonaws.com/${VERSION}/stack.yaml"
  launch="https://${region}.console.aws.amazon.com/cloudformation/home?region=${region}#/stacks/create/review?templateURL=${url}&stackName=ct-nl-investigator&param_ArtifactVersion=${VERSION}"
  echo "   done. Launch Stack URL ($region):"
  echo "   $launch"
done
