#!/usr/bin/env bash
# Isolated Debian ARM64 VM; no host or public network is involved.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && -c /dev/net/tun ]]
mode=$1
[[ $mode == old || $mode == refresh ]]
OUT=$(realpath -m "$2")
mkdir -p "$OUT"
[[ -z $(ls -A "$OUT") ]]
LAB=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$LAB/../dns-geo" && pwd)
# shellcheck source=../dns-geo/network.sh
source "$ROOT/network.sh"
printf 'old\n' >"$OUT/record-state"
ip netns exec "$R" python3 -B "$LAB/peer.py" ru "$OUT/record-state" >"$OUT/ru-peer.log" &
ip netns exec "$F" python3 -B "$LAB/peer.py" "fi" "$OUT/record-state" >"$OUT/fi-peer.log" &
{
    uname -srmo
    sing-box version
    dpkg-query -W python3-dnspython
} >"$OUT/version.txt"
gw sing-box check -c "$ROOT/config.json"
ip netns exec "$G" sing-box run -c "$ROOT/config.json" >"$OUT/engine.log" 2>&1 &
engine=$!
for _ in {1..80}; do
    ip -n "$G" link show hestia0 >/dev/null 2>&1 && break
    sleep .05
done
gw ip route add 198.18.0.0/15 dev hestia0
if [[ $mode == old ]]; then cache="$ROOT/fixture.py"; else cache="$LAB/cache.py"; fi
ip netns exec "$G" python3 -B "$cache" gateway "$OUT/fi-unavailable" >"$OUT/decisions.log" 2>&1 &
for log in ru-peer fi-peer decisions; do
    for _ in {1..80}; do
        grep -qs 'ready' "$OUT/$log.log" && break
        sleep .05
    done
    grep -q ready "$OUT/$log.log"
done
caps=()
for dev in lan0 ru0 fi0; do
    ip netns exec "$G" tcpdump -U --immediate-mode -Z root -ni "$dev" -s0 -w "$OUT/$dev.pcap" 'port 53 or port 19091' 2>"$OUT/$dev.capture.log" &
    caps+=("$!")
    for _ in {1..100}; do
        grep -qs listening "$OUT/$dev.capture.log" && break
        sleep .05
    done
    grep -q listening "$OUT/$dev.capture.log"
done
sha256sum "$cache" | cut -d' ' -f1 >"$OUT/cache.sha256"
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-before"
ip netns exec "$C" python3 -B "$LAB/client.py" "$mode" "$OUT"
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-after"
kill -INT "${caps[@]}"
for cap in "${caps[@]}"; do wait "$cap"; done
for dev in lan0 ru0 fi0; do grep -qx '0 packets dropped by kernel' "$OUT/$dev.capture.log"; done
python3 -B "$LAB/verify.py" "$mode" "$OUT" | tee "$OUT/verification.txt"
