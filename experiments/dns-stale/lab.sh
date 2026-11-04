#!/usr/bin/env bash
# Disposable Debian ARM64 guest. Arguments: strict|stale, unused output directory.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && -c /dev/net/tun ]]
mode=$1
[[ $mode == strict || $mode == stale ]]
OUT=$(realpath -m "$2")
mkdir -p "$OUT"
[[ -z $(ls -A "$OUT") ]]
LAB=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$LAB/../dns-geo" && pwd)
# shellcheck source=../dns-geo/network.sh
source "$ROOT/network.sh"
printf '{}\n' >"$OUT/authority-state.json"
ip netns exec "$R" python3 -B "$LAB/authority.py" ru "$OUT/authority-state.json" >"$OUT/ru-peer.log" &
ip netns exec "$F" python3 -B "$LAB/authority.py" "fi" "$OUT/authority-state.json" >"$OUT/fi-peer.log" &
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
args=()
if [[ $mode == stale ]]; then args=(--stale-seconds 24); fi
printf '{"upstream_ttl_seconds":2,"stale_seconds":%s}\n' "$([[ $mode == stale ]] && echo 24 || echo 0)" >"$OUT/settings.json"
ip netns exec "$G" python3 -B "$LAB/cache.py" gateway "${args[@]}" --down "$OUT/fi-unavailable" >"$OUT/decisions.log" 2>&1 &
for log in fi-peer ru-peer decisions; do
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
sha256sum "$ROOT/fixture.py" "$ROOT/../dns-rotation/cache.py" "$LAB/cache.py" >"$OUT/code.sha256"
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-before"
ip netns exec "$C" python3 -B "$LAB/client.py" "$mode" "$OUT"
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-after"
kill -INT "${caps[@]}"
for cap in "${caps[@]}"; do wait "$cap"; done
for dev in lan0 ru0 fi0; do grep -qx '0 packets dropped by kernel' "$OUT/$dev.capture.log"; done
python3 -B "$LAB/verify.py" "$mode" "$OUT" | tee "$OUT/verification.txt"
