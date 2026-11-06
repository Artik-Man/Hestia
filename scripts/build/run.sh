#!/usr/bin/env bash
# Build both application targets without deploying or contacting any stand.
set -euo pipefail
exec python3 "$(dirname "$0")/run.py" "$@"
