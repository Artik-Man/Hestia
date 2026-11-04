#!/usr/bin/env bash
# Only in a disposable Debian ARM64 guest. Arguments: demand|warm, new output directory.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && -c /dev/net/tun ]]
mode=$1
[[ $mode == warm || $mode == demand || $mode == superseded ]]
OUT=$(realpath -m "$2")
mkdir -p "$OUT"
[[ -z $(ls -A "$OUT") ]]
LAB=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$LAB/../dns-geo" && pwd)
rotation=$(cd "$LAB/../dns-rotation" && pwd)
warm=$(cd "$LAB/../dns-warm" && pwd)
program=$warm/cache.py
if [[ $mode == superseded ]]; then program=${SPLIT_WARM_GATEWAY:?path to earlier warm cache}; fi
# shellcheck source=../dns-geo/network.sh
source "$ROOT/network.sh"
printf 'first\n' >"$OUT/ru-state"
printf '{"min_visits":3,"window_seconds":24,"refresh_seconds":1}\n' >"$OUT/settings.json"
ip netns exec "$R" python3 -B "$LAB/authority.py" ru "$OUT/ru-state" >"$OUT/ru-peer.log" &
ip netns exec "$F" python3 -B "$LAB/authority.py" "fi" "$OUT/ru-state" >"$OUT/fi-peer.log" &
{
    uname -srmo
    sing-box version
    dpkg-query -W python3-dnspython
} >"$OUT/version.txt"
python3 - "$ROOT/config.json" "$OUT/sing-box.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
rules=c["route"]["rules"]
rules.insert(-2,{"ip_cidr":"203.0.113.33/32","action":"route","outbound":"ru-out"})
with open(sys.argv[2],"w") as f: json.dump(c,f,indent=2)
PY
gw sing-box check -c "$OUT/sing-box.json"
ip netns exec "$G" sing-box run -c "$OUT/sing-box.json" >"$OUT/engine.log" 2>&1 &
engine=$!
for _ in {1..80}; do
    ip -n "$G" link show hestia0 >/dev/null 2>&1 && break
    sleep .05
done
gw ip route add 198.18.0.0/15 dev hestia0
if [[ $mode == demand ]]; then
    ip netns exec "$G" python3 -B "$rotation/cache.py" gateway "$OUT/fi-down" >"$OUT/decisions.log" 2>&1 &
else
    ip netns exec "$G" python3 -B "$program" gateway --config "$OUT/settings.json" --down "$OUT/fi-down" >"$OUT/decisions.log" 2>&1 &
fi
for log in ru-peer fi-peer decisions; do
    for _ in {1..80}; do
        grep -qs ready "$OUT/$log.log" && break
        sleep .05
    done
    grep -q ready "$OUT/$log.log"
done
caps=()
for dev in lan0 ru0 fi0; do
    ip netns exec "$G" tcpdump -U --immediate-mode -Z root -ni "$dev" -s0 -w "$OUT/$dev.pcap" 'port 53 or port 19091' 2>"$OUT/$dev.capture.log" &
    caps+=("$!")
    for _ in {1..80}; do
        grep -qs listening "$OUT/$dev.capture.log" && break
        sleep .05
    done
    grep -q listening "$OUT/$dev.capture.log"
done
sha256sum "$ROOT/fixture.py" "$rotation/cache.py" >"$OUT/code.sha256"
if [[ $mode != demand ]]; then sha256sum "$program" >>"$OUT/code.sha256"; fi
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-before"
ip netns exec "$C" python3 -B "$LAB/client.py" "$mode" "$OUT"
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-after"
kill -INT "${caps[@]}"
for cap in "${caps[@]}"; do wait "$cap"; done
for dev in lan0 ru0 fi0; do grep -qx '0 packets dropped by kernel' "$OUT/$dev.capture.log"; done
python3 -B "$LAB/verify.py" "$mode" "$OUT" | tee "$OUT/verification.txt"
