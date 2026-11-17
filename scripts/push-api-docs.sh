#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
SPEC_ID="${POSTMAN_SPEC_ID:-9c95519e-1a96-4e3d-bd86-35053fa539b4}"
SPEC=proto/openapi/auth.swagger.yaml
postman spec lint "$SPEC" --issueType=syntax
postman spec file update "$SPEC_ID" index.yaml < "$SPEC"
