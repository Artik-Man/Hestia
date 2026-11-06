#!/usr/bin/env bash
# Run only in a disposable Linux guest. All routes and interfaces are confined to namespaces.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$(mktemp -d)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[[ -z $(ls -A "$OUT") && $EUID == 0 && -c /dev/net/tun ]]
BIN=${SING_BOX:-$(command -v sing-box)}
CONFIG="$ROOT/config.json"
source "$ROOT/fixture.sh"
# select_exit sets the Finland selector, reads it back and records the reason for the change.
select_exit() {
    local name=$1 reason=$2 current
    event "select requested=$name reason=$reason"
    gw curl --noproxy '*' --fail --silent --show-error --max-time 3 -X PUT \
        -H 'Content-Type: application/json' -d "{\"name\":\"$name\"}" http://127.0.0.1:9090/proxies/finland
    current=$(gw curl --noproxy '*' --fail --silent --show-error --max-time 3 http://127.0.0.1:9090/proxies/finland | python3 -c 'import json,sys; print(json.load(sys.stdin)["now"])')
    [[ $current == "$name" ]]
    event "select applied=$current"
}
# start_captures writes this array through a nameref.
# shellcheck disable=SC2034
continuous=()
start_captures continuous continuous
client init "$OUT/state.json" >"$OUT/init.log"
select_exit fi1-out initial_priority
phase warm
carrier fi1 down
select_exit fi2-out primary_unavailable
phase failover
carrier fi2 down
select_exit deny group_unavailable
phase blocked
phase control
carrier fi2 up
phase gate
select_exit fi2-out reserve_recovered
phase recovery
kill -0 "$engine"
stop_captures continuous continuous
python3 "$ROOT/probes.py" verify "$OUT" | tee "$OUT/verification.txt"
