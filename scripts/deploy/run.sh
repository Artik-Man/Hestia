#!/usr/bin/env bash
# Deploy only the supplied built artifact to the explicitly selected stand.
set -euo pipefail
exec python3 "$(dirname "$0")/run.py" "$@"
