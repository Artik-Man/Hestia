#!/usr/bin/env bash
# Disposable Linux guest with systemd as PID 1. All test artifacts are synthetic.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && -c /dev/net/tun ]]
CTL=$(realpath "$1")
OUT=$(realpath -m "$2")
mkdir -p "$OUT"
[[ -x "$CTL" && -z $(ls -A "$OUT") ]]
LAB=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$LAB/../failover" && pwd)
BIN=${SING_BOX:-$(command -v sing-box)}
CONFIG="$OUT/sing-box.json"
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
run=$(mktemp -d /run/hestia-svc-XXXXXX)
bindir=$(mktemp -d /usr/local/lib/hestia-svc-XXXXXX)
unit="${run##*/}.service"
unitfile="/run/systemd/system/$unit"
# service_cleanup stops the temporary systemd service, removes its test unit and releases the shared lab resources.
service_cleanup() {
    systemctl stop "$unit" >/dev/null 2>&1 || true
    rm -f -- "$unitfile" "$unitfile.d/lab.conf"
    rmdir -- "$unitfile.d" 2>/dev/null || true
    systemctl daemon-reload
    rm -rf -- "$run" "$bindir"
    cleanup
}
trap service_cleanup EXIT
chmod 755 "$run" "$bindir"
install -m 755 "$CTL" "$bindir/hestia"
sha256sum "$CTL" | cut -d' ' -f1 >"$OUT/controller.sha256"
install -m 644 "$LAB/../../../deploy/systemd/hestia.service" "$unitfile"
mkdir "$unitfile.d"
cat >"$unitfile.d/lab.conf" <<UNIT
[Unit]
After=
Wants=
[Service]
NetworkNamespacePath=/run/netns/$G
ExecStart=
ExecStart=$bindir/hestia -watch -config $run/snapshot.json -interval 200ms
UNIT
systemctl daemon-reload
systemctl cat "$unit" >"$OUT/unit.txt"
# mainpid returns the PID of the running test controller as recorded by systemd.
mainpid() { systemctl show --property MainPID --value "$unit"; }
# status returns the current target of the requested selector from the running engine.
status() {
    gw curl --noproxy '*' -fsS --max-time 2 "http://127.0.0.1:9090/proxies/$1" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["now"])'
}
# publish atomically publishes a snapshot and archives that exact version alongside its stage event.
publish() {
    local stage=$1 fi1=$2 fi2=$3 group=${4:-finland}
    cat >"$run/snapshot.new" <<JSON
{"groups":[{"id":"russia","exits":["ru"]},{"id":"finland","exits":["fi1-out","fi2-out"]}],"lists":[{"id":"fi-domains","group":"$group","masks":["*.fi.lab.test"]}],"healthy":{"ru":true,"fi1-out":$fi1,"fi2-out":$fi2}}
JSON
    cp "$run/snapshot.new" "$OUT/$stage.json"
    chmod 644 "$run/snapshot.new"
    mv -f "$run/snapshot.new" "$run/snapshot.json"
    event "publish $stage fi1=$fi1 fi2=$fi2 group=$group"
}
# observe waits for both groups to reach the expected selectors, then records the controller PID and observed state.
observe() {
    local stage=$1 fi=$2 pid
    for _ in {1..100}; do
        [[ $(status finland) == "$fi" && $(status russia) == ru ]] && break
        sleep .1
    done
    [[ $(status finland) == "$fi" && $(status russia) == ru ]]
    pid=$(mainpid)
    [[ $pid -gt 0 ]]
    printf '%s %s %s ru\n' "$stage" "$pid" "$fi" >>"$OUT/states.txt"
    event "stage=$stage pid=$pid finland=$fi russia=ru"
}
# capture starts tcpdump on the given gateway interface and records its PID after the listener is ready.
capture() {
    local label=$1 iface=$2 filter=$3
    ip netns exec "$G" tcpdump --immediate-mode -U -Z root -ni "$iface" -s0 -w "$OUT/$label.pcap" \
        "$filter" 2>"$OUT/$label.capture.log" &
    caps+=("$!")
    for _ in {1..100}; do
        grep -qs 'listening on' "$OUT/$label.capture.log" && break
        sleep .05
    done
    grep -q 'listening on' "$OUT/$label.capture.log"
}
caps=()
capture ingress lan0 'port 53 or port 19091'
capture api lo 'tcp dst port 9090'
# start_captures writes this array through a nameref.
# shellcheck disable=SC2034
continuous=()
start_captures continuous continuous
client init "$OUT/state.json" >"$OUT/init.log"
[[ $(status finland) == deny && $(status russia) == deny ]]
publish initial true true
systemctl start "$unit"
observe initial fi1-out
phase warm
carrier fi1 down
publish failover-snapshot false true
observe failover fi2-out
publish invalid true true missing
# Wait for real diagnostic; a delay alone would not prove the file was tried.
for _ in {1..100}; do
    journalctl -u "$unit" --no-pager -o cat >"$OUT/journal.tmp"
    grep -qiE 'invalid|unknown group' "$OUT/journal.tmp" && break
    sleep .1
done
grep -qiE 'invalid|unknown group' "$OUT/journal.tmp"
observe invalid fi2-out
phase failover
carrier fi2 down
publish outage false false
observe outage deny
phase blocked
phase control
carrier fi1 up
carrier fi2 up
observe gate deny
phase gate
publish restore false true
observe recovery fi2-out
phase recovery
# Hold the old target and replace the snapshot while the service is stopped.
systemctl stop "$unit"
[[ $(mainpid) == 0 && $(status finland) == fi2-out ]]
publish while-stopped true true
[[ $(status finland) == fi2-out ]]
systemctl start "$unit"
observe restart fi1-out
kill -0 "$engine"
stop_captures continuous continuous
kill -INT "${caps[@]}"
for pid in "${caps[@]}"; do wait "$pid"; done
for label in ingress api; do grep -qx '0 packets dropped by kernel' "$OUT/$label.capture.log"; done
systemctl stop "$unit"
journalctl -u "$unit" --no-pager -o cat >"$OUT/service.log"
rm -f "$OUT/journal.tmp"
python3 -B "$LAB/verify.py" "$OUT" | tee "$OUT/verification.txt"
