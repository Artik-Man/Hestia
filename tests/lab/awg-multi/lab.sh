#!/usr/bin/env bash
# Run as root inside fresh PID, mount and network namespaces on hestia-dev.
set -euo pipefail
umask 077
[[ $(hostname -s) == lima-hestia-dev && $$ == 1 && $(id -u) == 0 ]] || exit 1
[[ $# == 4 && -x $1 && -x $2 && -x $3 && -x $4 ]] || exit 1
hestia=$1
daemon=$2
tool=$3
singbox=$4
here=$(dirname "$(realpath "$0")")
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mkdir -p /run/hestia-awg /run/amneziawg
work=$(mktemp -d /run/lab.XXXXXXXX)
cp -a /etc "$work/etc"
mount --bind "$work/etc" /etc
# Exclude installed profiles and generated files from the private synthetic fixture.
mkdir -p /etc/hestia
mount -t tmpfs -o mode=0700 tmpfs /etc/hestia
mount -t tmpfs tmpfs /usr/local
install -d /usr/local/bin /usr/local/lib/hestia
install -m 0755 "$daemon" /usr/local/lib/hestia/amneziawg-go
install -m 0755 "$tool" /usr/local/bin/awg
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
getent group hestia-snapshot >/dev/null || groupadd --system hestia-snapshot
chmod 0750 /run/hestia-awg
chgrp hestia-snapshot /run/hestia-awg
install -d -m 0700 /etc/hestia/awg
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ya.ru \
    -addext 'subjectAltName=DNS:ya.ru,DNS:group-a.lab,DNS:group-b.lab' -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
export SSL_CERT_FILE="$work/cert.pem"
ip link set lo up

# wait_file waits for the runtime or the control flow to produce a non-secret readiness marker.
wait_file() {
    local path=$1 pid=$2
    for ((attempt = 0; attempt < 150; attempt++)); do
        [[ ! -f $path ]] || return 0
        kill -0 "$pid" 2>/dev/null || return 1
        sleep 0.2
    done
    return 1
}

# configure_peer starts an isolated server and writes one root-private ready profile for the named runtime.
configure_peer() {
    local slot=$1 id=$2 ns="peer$1" config="/etc/hestia/awg/$2" protocol=wireguard params="" keepalive=""
    ip netns add "$ns"
    ip link add "lan$slot" type veth peer name "eth$slot"
    ip link set "eth$slot" netns "$ns"
    ip addr add "198.18.$slot.1/30" dev "lan$slot"
    ip link set "lan$slot" up
    ip -n "$ns" link set lo up
    ip -n "$ns" addr add "198.18.$slot.2/30" dev "eth$slot"
    ip -n "$ns" link set "eth$slot" up
    # A default route exists in both families so a direct leak is observable.
    if [[ $slot == 0 ]]; then
        ip route add default via 198.18.0.2
        ip -6 addr add fd77::1/64 dev lan0 nodad
        ip -n "$ns" -6 addr add fd77::2/64 dev eth0 nodad
        ip -6 route add default via fd77::2 dev lan0
    fi
    awg genkey >"$work/$id.client"
    awg pubkey <"$work/$id.client" >"$work/$id.client.pub"
    awg genkey >"$work/$id.server"
    awg pubkey <"$work/$id.server" >"$work/$id.server.pub"
    ip netns exec "$ns" /usr/local/lib/hestia/amneziawg-go -f "srv$slot" >/dev/null 2>&1 &
    local server_pid=$!
    for ((attempt = 0; attempt < 100; attempt++)); do
        if ip netns exec "$ns" awg show "srv$slot" public-key >/dev/null 2>&1; then break; fi
        kill -0 "$server_pid"
        sleep 0.1
    done
    ip netns exec "$ns" awg set "srv$slot" private-key "$work/$id.server" listen-port 51820 \
        peer "$(<"$work/$id.client.pub")" allowed-ips 10.77.0.2/32
    if [[ $slot == 1 ]]; then
        protocol=amneziawg
        keepalive="PersistentKeepalive = 25"
        params=$'Jc = 1\nJmin = 20\nJmax = 30'
        ip netns exec "$ns" awg set "srv$slot" jc 1 jmin 20 jmax 30
    fi
    ip -n "$ns" addr add 10.77.0.1/32 dev "srv$slot"
    ip -n "$ns" link set "srv$slot" up
    ip -n "$ns" route add 10.77.0.2/32 dev "srv$slot"
    ip netns exec "$ns" python3 "$here/peer.py" "$id" "$work/cert.pem" "$work/key.pem" &
    install -d -m 0700 "$config"
    cat >"$config/profile.conf" <<PROFILE
[Interface]
PrivateKey = $(<"$work/$id.client")
Address = 10.77.0.2/32
DNS = 10.77.0.1
$params
[Peer]
PublicKey = $(<"$work/$id.server.pub")
Endpoint = 198.18.$slot.2:51820
AllowedIPs = 0.0.0.0/0
$keepalive
PROFILE
    cat >"$config/metadata.json" <<METADATA
{"id":"$id","group":"test","priority":1,"status":"ready","type":"$protocol","ipv4Address":"10.77.0.2/32","dnsIPv4":"10.77.0.1","ipv6Blocked":false,"slot":$slot}
METADATA
}

configure_peer 0 tunnel-a
configure_peer 1 tunnel-b
ip rule add priority 800 from all lookup main
if "$hestia" -awg-runtime tunnel-b; then
    echo "earlier unmarked route bypass was accepted" >&2
    exit 1
fi
[[ ! -e /run/hestia-awg/routes.json.tunnel-b && ! -e /run/hestia-awg/ready.tunnel-b ]]
ip rule del priority 800 from all lookup main
# Scheme 3 uses earlier ingress rules that cannot match locally originated sockets.
ip rule add priority 1000 iif lan0 lookup 200
ip rule add priority 1001 iif lan1 lookup 201
echo "foreign catch-all rejected before mutation; distinct scheme-3-style ingress rules present"
before=$(ip route show table main)
"$hestia" -awg-runtime tunnel-a &
a_pid=$!
"$hestia" -awg-runtime tunnel-b &
b_pid=$!
wait_file /run/hestia-awg/ready.tunnel-a "$a_pid"
wait_file /run/hestia-awg/ready.tunnel-b "$b_pid"
[[ $(ip route show table main) == "$before" ]]
[[ $(awg show awg0 persistent-keepalive | cut -f2) == off ]]
[[ $(awg show awg1 persistent-keepalive | cut -f2) == 25 ]]
echo "WG without keepalive and AWG with 25s keepalive are ready; settings restored; main IPv4 table unchanged"
for slot in 0 1; do
    ip -4 route show table "$((202 + slot))"
    ip -6 route show table "$((202 + slot))"
    ip route get 10.77.0.1 mark "$((514 + slot))"
    ip route get "198.18.$slot.2"
done
python3 "$here/groups.py" "$here/profile.py" "$work/groups.json"
"$singbox" run -c "$work/groups.json" >"$work/singbox.log" 2>&1 &
router_pid=$!
# group_probe obtains the response body for one group via its real SOCKS ingress and selector.
group_probe() {
    local host=group-a.lab
    if [[ $1 == 20081 ]]; then host=group-b.lab; fi
    curl -fsS --max-time 4 --noproxy '' --socks5-hostname "127.0.0.1:$1" --cacert "$work/cert.pem" "https://$host/"
}
for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ $(group_probe 20080 2>/dev/null) == tunnel-a ]]; then break; fi
    if ! kill -0 "$router_pid" 2>/dev/null; then
        cat "$work/singbox.log" >&2
        exit 1
    fi
    sleep 0.1
done
[[ $(group_probe 20080) == tunnel-a && $(group_probe 20081) == tunnel-b ]]
echo "sing-box groups verified: client-0 -> tunnel-a, client-1 -> tunnel-b"
mkdir "$work/a" "$work/b"
touch "$work/b/finish"
python3 "$here/control.py" 1 tunnel-b "$work/cert.pem" "$work/b"
python3 "$here/control.py" --group 0 tunnel-a "$work/cert.pem" "$work/a" &
control_pid=$!
wait_file "$work/a/connected" "$control_pid"
kill -TERM "$b_pid"
wait "$b_pid" || true
[[ ! -e /run/hestia-awg/ready.tunnel-b && -s /run/hestia-awg/health.json.tunnel-a ]]
if ip route get 10.77.0.1 mark 515 || ip -6 route get fd77::2 mark 515; then
    echo "secondary marked flow can reach the underlay" >&2
    exit 1
fi
ip route get 10.77.0.1
ip -6 route get fd77::2
[[ $(group_probe 20080) == tunnel-a ]]
if group_probe 20081 >/dev/null 2>&1; then
    echo "stopped group leaked" >&2
    exit 1
fi
tcpdump -n -Z root -i lan0 -U -w "$work/underlay.pcap" 'udp dst port 15999 or udp dst port 16000' 2>"$work/tcpdump.log" &
capture_pid=$!
for ((attempt = 0; attempt < 50; attempt++)); do
    if grep -q 'listening on' "$work/tcpdump.log"; then break; fi
    kill -0 "$capture_pid"
    sleep 0.1
done
python3 "$here/leak.py"
for ((attempt = 0; attempt < 50; attempt++)); do
    if [[ $(tcpdump -nn -r "$work/underlay.pcap" 'udp dst port 15999' 2>/dev/null | wc -l) -eq 2 ]]; then break; fi
    sleep 0.1
done
kill -INT "$capture_pid"
wait "$capture_pid"
[[ $(tcpdump -nn -r "$work/underlay.pcap" 'udp dst port 15999' 2>/dev/null | wc -l) -eq 2 ]]
[[ $(tcpdump -nn -r "$work/underlay.pcap" 'udp dst port 16000' 2>/dev/null | wc -l) -eq 0 ]]
echo "underlay capture: two unmarked controls, zero marked packets; group 0 healthy, group 1 blocked"
echo "secondary unreachable for IPv4 and IPv6 with unmarked underlay alive"
# The staged candidate has no responding peer. Its deadline must abort startup while group A keeps its established stream.
install -m 0600 /etc/hestia/awg/tunnel-b/profile.conf "$work/good.conf"
sed -i 's/198.18.1.2:51820/198.18.1.2:51821/' /etc/hestia/awg/tunnel-b/profile.conf
if timeout 24 "$hestia" -awg-runtime tunnel-b; then
    echo "unreachable candidate incorrectly marked ready" >&2
    exit 1
else
    result=$?
    [[ $result == 1 ]]
fi
[[ ! -e /run/hestia-awg/ready.tunnel-b && $(group_probe 20080) == tunnel-a ]]
echo "candidate with unreachable peer rejected within deadline, original group stream alive"
install -m 0600 "$work/good.conf" /etc/hestia/awg/tunnel-b/profile.conf
"$hestia" -awg-runtime tunnel-b &
b_pid=$!
wait_file /run/hestia-awg/ready.tunnel-b "$b_pid"
python3 "$here/control.py" 1 tunnel-b "$work/cert.pem" "$work/b"
touch "$work/a/finish"
wait "$control_pid"
kill -TERM "$b_pid" "$a_pid"
wait "$a_pid" || true
wait "$b_pid" || true
echo "peer identity and same TLS session verified across neighbor stop/restart"
