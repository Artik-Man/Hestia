#!/usr/bin/env bash
# Run cleanup-safe UI acceptance through a dedicated loopback SSH tunnel to the existing dev VM.
set -euo pipefail
umask 077
[[ $# == 3 ]] || exit 2
repo=$(cd "$1" && pwd)
out=$(cd "$2" && pwd)
remote=$3
[[ $remote =~ ^/var/tmp/hestia-validation-[A-Za-z0-9._-]+$ ]] || exit 2
vm=${LIMACTL:-/private/tmp/hestia-vm-run/bin/limactl}
export LIMA_HOME="$HOME/.lima"
[[ $("$vm" shell hestia-dev -- hostname -s) == lima-hestia-dev ]] || exit 2
"$vm" shell hestia-dev -- sudo python3 "$remote/repo/tests/lab/dev-validation/acceptance.py" guard
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
[[ $port =~ ^[0-9]+$ ]] || exit 2
tunnel=
ui=
# cleanup terminates only this dedicated SSH process, leaving Lima's control connection untouched.
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -n $ui ]]; then
        kill -TERM "$ui" 2>/dev/null || :
        wait "$ui" 2>/dev/null || :
    fi
    if [[ -n $tunnel ]]; then
        kill "$tunnel" 2>/dev/null || :
        wait "$tunnel" 2>/dev/null || :
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ssh -F "$LIMA_HOME/hestia-dev/ssh.config" -S none -o ControlMaster=no -o ControlPath=none \
    -o ForkAfterAuthentication=no -o ExitOnForwardFailure=yes -o BatchMode=yes \
    -N -L "127.0.0.1:$port:127.0.0.1:8080" lima-hestia-dev >"$out/ui-tunnel.log" 2>&1 &
tunnel=$!
ready=0
for ((attempt = 0; attempt < 50; attempt++)); do
    kill -0 "$tunnel" 2>/dev/null || exit 1
    if curl --noproxy '*' -fsS --max-time 1 "http://127.0.0.1:$port/api/groups-and-rules" >/dev/null; then
        ready=1
        break
    fi
    sleep .1
done
[[ $ready == 1 ]] || exit 1
HESTIA_VALIDATION_REPO="$repo" HESTIA_E2E_URL="http://127.0.0.1:$port" \
    node "$repo/tests/lab/dev-validation/ui_accept.mjs" &
ui=$!
wait "$ui"
ui=
"$vm" shell hestia-dev -- sudo python3 "$remote/repo/tests/lab/dev-validation/acceptance.py" guard
echo 'PASS installed UI and owned-list cleanup'
