#!/usr/bin/env bash
# Run inside a disposable Linux VM with sing-box, iproute2, openssl and Python.
set -euo pipefail
[[ $(hostname -s) == lima-hestia-dev && $EUID == 0 ]]
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
chmod 700 "$work"
cd "$work"
box=${SING_BOX:?Set SING_BOX to the verified sing-box executable}
names=()
pids=()
# cleanup retires processes and namespaces created only by this run.
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || :; done
    for name in "${names[@]}"; do ip netns del "$name"; done
    rm -rf "$work"
}
trap cleanup EXIT
for ns in client gateway server witness; do
    name=hy2-$ns-$$
    ip netns add "$name"
    names+=("$name")
    ip -n "$name" link set lo up
done
# link connects two experiment namespaces using a dedicated point-to-point subnet.
link() {
    local left=hy2-$1-$$ right=hy2-$2-$$ dev=$3 peer=${6:-peer}
    ip -n "$left" link add "$dev" type veth peer name "$peer" netns "$right"
    ip -n "$left" addr add "$4/30" dev "$dev"
    ip -n "$right" addr add "$5/30" dev "$peer"
    ip -n "$left" link set "$dev" up
    ip -n "$right" link set "$peer" up
}
link client gateway lan 192.0.2.1 192.0.2.2
link gateway server wan 203.0.113.1 203.0.113.2
link server witness uplink 198.51.100.1 198.51.100.2
if [[ ${HESTIA_UNDERLAYS:-} == ordered ]]; then
    : "${HESTIA_WATCH:?Use the gateway controller from the same build}"
    link gateway server wan2 203.0.113.5 203.0.113.6 secondary
    ip -n "hy2-gateway-$$" rule add oif wan2 table 202
    ip -n "hy2-gateway-$$" route add table 202 203.0.113.2/32 via 203.0.113.6 dev wan2
    ip netns exec "hy2-server-$$" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.secondary.rp_filter=0
fi
ip -n "hy2-client-$$" route add default via 192.0.2.2
ip netns exec "hy2-gateway-$$" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "hy2-server-$$" sysctl -qw net.ipv4.ip_forward=1
ip -n "hy2-gateway-$$" route add 198.51.100.0/30 via 203.0.113.2
ip -n "hy2-server-$$" route add 192.0.2.0/30 via 203.0.113.1
ip -n "hy2-witness-$$" route add default via 198.51.100.1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=lab -addext subjectAltName=IP:203.0.113.2 -keyout key.pem -out cert.pem 2>/dev/null
cat >server.json <<EOF
{"inbounds":[{"type":"hysteria2","listen":"0.0.0.0","listen_port":1443,"users":[{"password":"lab-only"}],"tls":{"enabled":true,"certificate_path":"$work/cert.pem","key_path":"$work/key.pem"}}],"outbounds":[{"type":"direct"}]}
EOF
python3 - "$here" <<'PY'
import os, json, secrets, sys
from pathlib import Path
here = Path(sys.argv[1])
profile = json.loads((here / "../../../deploy/scheme3/guest-profile.json").read_text())
profile["interfaces"] = [{"type":"direct","id":"physical","bind_interface":"wan"}]
tag = "a1234567-1234-4123-8123-123456789abc"
profile["hysteria2"] = [{"id":tag,"name":"Испытание","underlay":"physical","server":"203.0.113.2","port":1443,"password":"lab-only","probeSecret":secrets.token_hex(32),"certificatePEM":Path("cert.pem").read_text()}]
profile["groups"] = [{"id":"default","exits":[tag],"defaultExit":tag},{"id":"other","exits":["physical"],"defaultExit":"physical"}]
profile["healthy"] = {tag:True,"physical":True}
if os.environ.get("HESTIA_WATCH"):
    profile["groups"] = [{"id":"default","exits":[tag,"physical"],"defaultExit":tag}]
    profile["healthy"]["physical"] = False
if os.environ.get("HESTIA_UNDERLAYS") == "ordered":
    profile["interfaces"].append({"type":"direct","id":"backup","bind_interface":"wan2"})
    tunnel = profile["hysteria2"][0]
    del tunnel["underlay"]
    # The second candidate is itself a TLS-verified VPN via the other veth.
    reserve = "b1234567-1234-4123-8123-123456789abc"
    profile["hysteria2"].append({**tunnel,"id":reserve,"name":"Резервный туннель","underlay":"backup",
                                 "server":"203.0.113.6","serverName":"203.0.113.2","probeSecret":secrets.token_hex(32)})
    tunnel["underlays"] = ["physical",reserve]
    profile["healthy"] = {tag:True,reserve:True,"physical":True,"backup":True}
    profile["groups"] = [{"id":"default","exits":[tag],"defaultExit":tag},{"id":"other","exits":["physical","backup",reserve],"defaultExit":"physical"}]
Path("profile.json").write_text(json.dumps(profile))
PY
mkdir output
python3 -I "$here/../../../deploy/profile.py" profile.json output .
"$box" check -c output/sing-box.json
ip netns exec "hy2-server-$$" "$box" run -c server.json >server.log 2>&1 &
server_pid=$!
pids+=("$server_pid")
for transport in SOCK_STREAM SOCK_DGRAM; do
    ip netns exec "hy2-witness-$$" python3 "$here/traffic.py" "$transport" "$work/$transport" &
    pids+=("$!")
done
ip netns exec "hy2-gateway-$$" "$box" run -c output/sing-box.json >gateway.log 2>&1 &
pids+=("$!")
for ((i = 0; i < 100; i++)); do
    if [[ -f SOCK_STREAM && -f SOCK_DGRAM ]] && ip -n "hy2-gateway-$$" link show hestia0 >/dev/null 2>&1 && ip netns exec "hy2-server-$$" ss -Huln | grep -q ':1443 '; then break; fi
    sleep 0.1
done
ip netns exec "hy2-client-$$" python3 "$here/traffic.py" check 192.0.2.1
ip -n "hy2-gateway-$$" rule add iif peer lookup 201
ip -n "hy2-gateway-$$" route add table 201 198.51.100.2/32 dev hestia0
if [[ ${HESTIA_UNDERLAYS:-} != ordered ]]; then
    ip netns exec "hy2-client-$$" python3 "$here/traffic.py" check 198.51.100.1
fi
if [[ -n ${HESTIA_WATCH:-} ]]; then
    ip -n "hy2-server-$$" addr add 1.1.1.1/32 dev lo
    ip netns exec "hy2-server-$$" python3 "$here/traffic.py" dns-ready &
    pids+=("$!")
    mkdir quality
    python3 -I "$here/../../../deploy/profile.py" --quality-paths output/sing-box.json quality
    # Isolate the controller's fixed /run and settings paths from the rest of the VM.
    # Expand the controller path and working directory inside the private namespace.
    # shellcheck disable=SC2016
    ip netns exec "hy2-gateway-$$" unshare --mount --propagation private -- bash -ec '
        mount -t tmpfs tmpfs /run
        mkdir /run/hestia-quality
        mount --bind "$PWD/quality" /run/hestia-quality
        mount -t tmpfs tmpfs /var/lib
        mkdir /var/lib/hestia-quality-settings
        printf "%s\n" "{\"windowMinutes\":60,\"checks\":[]}" >/var/lib/hestia-quality-settings/settings.json
        exec "$1" -watch -quality -interval 200ms -config output/snapshot.json
    ' _ "$HESTIA_WATCH" >watch.log 2>&1 &
    pids+=("$!")
    if [[ ${HESTIA_UNDERLAYS:-} == ordered ]]; then
        # path waits for the actual sing-box selector and tests client TCP and UDP through it.
        path() {
            ip netns exec "hy2-gateway-$$" python3 "$here/traffic.py" transport "$1"
            if [[ $1 != deny ]]; then
                python3 "$here/traffic.py" selected quality/report.json a1234567-1234-4123-8123-123456789abc
            fi
            ip netns exec "hy2-client-$$" python3 "$here/traffic.py" check "$2"
        }
        # filter changes only outer QUIC to the lab peer on one interface; the device stays up.
        filter() {
            ip netns exec "hy2-gateway-$$" iptables "$1" OUTPUT -o "$2" -p udp --dport 1443 -j DROP
        }
        path physical 198.51.100.1
        filter -I wan
        path b1234567-1234-4123-8123-123456789abc 198.51.100.1
        filter -I wan2
        path deny blocked
        filter -D wan2
        path b1234567-1234-4123-8123-123456789abc 198.51.100.1
        filter -D wan
        path physical 198.51.100.1
        exit 0
    fi
    # First wait for positive authenticated readiness while the reserve is administratively down.
    python3 "$here/traffic.py" selected quality/report.json a1234567-1234-4123-8123-123456789abc
    python3 - <<'PYWATCH'
import json
from pathlib import Path
target = Path("output/snapshot.json")
snapshot = json.loads(target.read_text())
snapshot["healthy"]["physical"] = True
temp = target.with_suffix(".tmp")
temp.write_text(json.dumps(snapshot))
temp.replace(target)
PYWATCH
fi
kill "$server_pid"
wait "$server_pid" || :
if [[ -n ${HESTIA_WATCH:-} ]]; then
    python3 "$here/traffic.py" selected quality/report.json physical
    ip netns exec "hy2-client-$$" python3 "$here/traffic.py" check 203.0.113.1
else
    ip netns exec "hy2-client-$$" python3 "$here/traffic.py" check blocked
fi
