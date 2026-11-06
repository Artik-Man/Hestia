#!/usr/bin/env bash
# Run only as root on disposable Debian ARM64 hestia-dns-geo.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && $(uname -m) == aarch64 && -c /dev/net/tun ]]
case $(hostname -s) in
    lima-hestia-dns-geo | hestia-dns-geo) ;;
    *)
        echo "This experiment requires the isolated hestia-dns-geo guest" >&2
        exit 2
        ;;
esac
mode=$1
[[ $mode == dns || $mode == engine || $mode == engine-persist ]]
OUT=$(realpath -m "$2")
mkdir -p "$OUT"
[[ -z $(ls -A "$OUT") ]]
LAB=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$LAB/../dns-geo" && pwd)
warm=$(cd "$LAB/../dns-warm" && pwd)
rotation=$(cd "$LAB/../dns-rotation" && pwd)
# shellcheck source=../dns-geo/network.sh
source "$ROOT/network.sh"
printf 'second\n' >"$OUT/ru-state"
printf '{"min_visits":2,"window_seconds":10,"refresh_seconds":8}\n' >"$OUT/settings.json"
printf '%s\n' "$mode" >"$OUT/mode"
{
    uname -srmo
    sing-box version
    dpkg-query -W python3-dnspython
} >"$OUT/version.txt"
python3 - "$ROOT/config.json" "$OUT/sing-box.json" "$mode" "$OUT" <<'PY'
import json,sys
from pathlib import Path
source, dest, mode, directory = sys.argv[1:]
c=json.loads(Path(source).read_text())
if mode=="engine-persist":
    c["experimental"]={"cache_file":{"enabled":True,"path":str(Path(directory)/"aliases.db"),"store_fakeip":True,"store_dns":False}}
Path(dest).write_text(json.dumps(c,indent=2)+"\n")
PY
gw sing-box check -c "$OUT/sing-box.json"
# start_engine launches a new TUN process, waits for its interface and installs the lab-only FakeIP route.
start_engine() {
    ip netns exec "$G" sing-box run -c "$OUT/sing-box.json" >"$OUT/engine-$1.log" 2>&1 &
    engine=$!
    for _ in {1..150}; do
        kill -0 "$engine" || {
            cat "$OUT/engine-$1.log" >&2
            return 1
        }
        if ip -n "$G" link show hestia0 >/dev/null 2>&1; then break; fi
        sleep .04
    done
    ip -n "$G" link show hestia0 >/dev/null
    ip -n "$G" route replace 198.18.0.0/15 dev hestia0
}
# start_cache launches the unmodified warming prototype and waits until both DNS listeners report ready.
start_cache() {
    ip netns exec "$G" python3 -B "$warm/cache.py" gateway --config "$OUT/settings.json" --down "$OUT/fi-down" >"$OUT/cache-$1.log" 2>&1 &
    cache=$!
    for _ in {1..150}; do
        kill -0 "$cache" || {
            cat "$OUT/cache-$1.log" >&2
            return 1
        }
        if grep -qs '"ready"' "$OUT/cache-$1.log"; then return; fi
        sleep .04
    done
    return 1
}
# identity records both Linux PID and process start tick, which distinguishes a restarted process from a reused PID.
identity() {
    awk '{print $1,$22}' "/proc/$engine/stat" "/proc/$cache/stat" >"$OUT/process-$1.txt"
}
ip netns exec "$R" python3 -B "$LAB/client.py" authority ru "$OUT/ru-state" >"$OUT/ru-peer.log" &
ip netns exec "$F" python3 -B "$LAB/client.py" authority "fi" "$OUT/ru-state" >"$OUT/fi-peer.log" &
for group in ru "fi"; do
    for _ in {1..150}; do
        grep -qs '"ready"' "$OUT/$group-peer.log" && break
        sleep .04
    done
    grep -q '"ready"' "$OUT/$group-peer.log"
done
start_engine 1
start_cache 1
identity before
caps=()
for nic in lan0 ru0 fi0; do
    ip netns exec "$G" tcpdump -U --immediate-mode -Z root -ni "$nic" -s0 -w "$OUT/$nic.pcap" 'port 53 or port 19091' 2>"$OUT/$nic.capture.log" &
    caps+=("$!")
    for _ in {1..100}; do
        grep -qs 'listening on' "$OUT/$nic.capture.log" && break
        sleep .05
    done
    grep -q 'listening on' "$OUT/$nic.capture.log"
done
sha256sum "$LAB"/{lab.sh,client.py,verify.py} "$warm/cache.py" "$rotation/cache.py" "$ROOT"/{fixture.py,network.sh} "$LAB/../dns-split-warm/authority.py" "$rotation/peer.py" >"$OUT/code.sha256"
ip netns exec "$C" python3 -B "$LAB/client.py" before "$OUT"
if [[ $mode == dns ]]; then
    kill -TERM "$cache"
    wait "$cache" || [[ $? == 143 ]]
    start_cache 2
else
    kill -TERM "$engine"
    wait "$engine" || [[ $? == 143 ]]
    start_engine 2
fi
identity after
ip netns exec "$C" python3 -B "$LAB/client.py" after "$OUT"
kill -INT "${caps[@]}"
for pid in "${caps[@]}"; do wait "$pid"; done
for nic in lan0 ru0 fi0; do grep -qx '0 packets dropped by kernel' "$OUT/$nic.capture.log"; done
python3 -B "$LAB/verify.py" "$OUT" | tee "$OUT/verification.txt"
