#!/usr/bin/env bash
# Build the orchestrator Lambda package -> dist/backend.zip
# Deps are fetched as Lambda-compatible manylinux wheels (pydantic-core is native),
# so this runs on macOS/Linux without Docker. Set LAMBDA_ARCH=aarch64 for arm64 Lambdas.
set -euo pipefail

# Repo root is three levels up: deploy/serverless/scripts/ -> repo root.
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BUILD="$ROOT/build/backend"
DIST="$ROOT/dist"
ARCH="${LAMBDA_ARCH:-x86_64}"          # x86_64 (default) or aarch64
PY="${LAMBDA_PY:-3.13}"
PIP="${PIP:-pip3}"

rm -rf "$BUILD"
mkdir -p "$BUILD" "$DIST"

echo "==> installing deps ($ARCH, py$PY) into $BUILD"
"$PIP" install \
  --platform "manylinux2014_${ARCH}" \
  --python-version "$PY" \
  --implementation cp \
  --only-binary=:all: \
  --upgrade \
  --target "$BUILD" \
  -r "$ROOT/backend/requirements-lambda.txt"

echo "==> adding application code"
cp "$ROOT/backend/main.py" "$BUILD/"

echo "==> zipping"
rm -f "$DIST/backend.zip"
( cd "$BUILD" && zip -qr "$DIST/backend.zip" . -x '*.pyc' -x '*/__pycache__/*' )

echo "built $DIST/backend.zip ($(du -h "$DIST/backend.zip" | cut -f1))"
