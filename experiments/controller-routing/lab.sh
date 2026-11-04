#!/usr/bin/env bash
# Run only in the disposable guest. Usage: bash lab.sh /path/to/hestia empty-output-dir
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && -c /dev/net/tun ]]
CTL=$(realpath "$1")
OUT=$(realpath -m "$2")
mkdir -p "$OUT"
[[ -x "$CTL" && -z $(ls -A "$OUT") ]]
ROOT=$(cd "$(dirname "$0")/../failover" && pwd)
BIN=${SING_BOX:-$(command -v sing-box)}
CONFIG="$OUT/sing-box.json"
# Begin in deny to ensure the first successful probe required a real controller change.
python3 - "$ROOT/config.json" "$CONFIG" <<'PY'
import json,sys
cfg=json.load(open(sys.argv[1]))
next(o for o in cfg["outbounds"] if o["tag"] == "finland")["default"] = "deny"
cfg["outbounds"].append({"type":"selector","tag":"russia","outbounds":["ru","deny"],"default":"deny"})
next(r for r in cfg["route"]["rules"] if r.get("domain") == "ru.lab.test")["outbound"] = "russia"
with open(sys.argv[2],"w") as f:
    json.dump(cfg,f,indent=2)
PY
# shellcheck source=../failover/fixture.sh
source "$ROOT/fixture.sh"
sha256sum "$CTL" | cut -d" " -f1 >"$OUT/controller.sha256"
ip netns exec "$G" tcpdump --immediate-mode -U -Z root -ni lan0 -s0 -w "$OUT/ingress.pcap" \
    'port 53 or port 19091' 2>"$OUT/ingress.capture.log" &
ingress=$!
for _ in {1..100}; do
    grep -qs 'listening on' "$OUT/ingress.capture.log" && break
    sleep .05
done
grep -q 'listening on' "$OUT/ingress.capture.log"

# status returns the current target of the requested selector from the running engine.
status() {
    gw curl --noproxy '*' -fsS --max-time 3 "http://127.0.0.1:9090/proxies/${1:-finland}" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["now"])'
}
# snapshot writes the stage’s group availability and domain-list assignment into the controller input file.
snapshot() {
    local stage=$1 fi1=$2 fi2=$3 group=${4:-finland}
    cat >"$OUT/$stage-config.json" <<JSON
{"groups":[{"id":"russia","exits":["ru"]},{"id":"finland","exits":["fi1-out","fi2-out"]}],"lists":[{"id":"fi-domains","group":"$group","masks":["*.fi.lab.test"]}],"healthy":{"ru":true,"fi1-out":$fi1,"fi2-out":$fi2}}
JSON
}
# apply runs the Go controller in the gateway namespace and stores its confirmed selector decision for the stage.
apply() {
    local stage=$1 fi1=$2 fi2=$3 expected=$4
    snapshot "$stage" "$fi1" "$fi2"
    event "controller stage=$stage fi1=$fi1 fi2=$fi2 before=$(status)"
    gw "$CTL" -config "$OUT/$stage-config.json" -domain fi.lab.test >"$OUT/$stage-decision.json"
    current=$(status)
    event "controller stage=$stage observed_selector=$current"
    [[ $current == "$expected" ]]
}
# start_captures writes this array through a nameref.
# shellcheck disable=SC2034
continuous=()
start_captures continuous continuous
client init "$OUT/state.json" >"$OUT/init.log"
[[ $(status) == deny ]]
[[ $(status russia) == deny ]]
snapshot ru true true
gw "$CTL" -config "$OUT/ru-config.json" -domain ru.lab.test >"$OUT/ru-decision.json"
[[ $(status russia) == ru ]]
event "controller stage=ru-default observed_selector=ru"
apply warm true true fi1-out
phase warm
carrier fi1 down
apply failover false true fi2-out
snapshot invalid true true missing
if gw "$CTL" -config "$OUT/invalid-config.json" -domain fi.lab.test >"$OUT/invalid.stdout" 2>"$OUT/invalid.stderr"; then
    echo "Invalid active list accepted" >&2
    exit 1
fi
[[ $(status) == fi2-out ]]
event "invalid config rejected; selector still fi2-out"
phase failover
carrier fi2 down
apply blocked false false deny
phase blocked
phase control
carrier fi1 up
carrier fi2 up
[[ $(status) == deny ]]
for iface in fi1 fi2; do
    [[ $(gw cat "/sys/class/net/$iface/carrier") == 1 ]]
done
event "both FI carriers up while selector still deny"
phase gate
apply recovery false true fi2-out
phase recovery
kill -0 "$engine"
stop_captures continuous continuous
kill -INT "$ingress"
wait "$ingress"
grep -qx '0 packets dropped by kernel' "$OUT/ingress.capture.log"
python3 "$(dirname "$0")/verify.py" "$OUT" | tee "$OUT/verification.txt"
