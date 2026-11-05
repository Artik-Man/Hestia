#!/usr/bin/env bash
# Run as PID 1 in private mount, network and PID namespaces of the owner's development VM.
set -euo pipefail
umask 077
[[ $(hostname -s) == lima-hestia-load-01 && $$ == 1 && $(id -u) == 0 ]] || exit 1
[[ ($# == 5 || ($# == 6 && ($6 == --automatic-control || $6 == --native-parent || $6 == --udp-loss || $6 == --awg-padding))) && -x $1 && -x $2 && -x $3 && -x $4 && -r $5 ]] || exit 1
hestia=$(realpath "$1")
daemon=$(realpath "$2")
tool=$(realpath "$3")
singbox=$(realpath "$4")
compiler=$(realpath "$5")
here=$(dirname "$(realpath "$0")")
peer_fixture=$here/../awg-multi/peer.py
[[ -f $peer_fixture ]]
mount --make-rprivate /
mount -t tmpfs tmpfs /run
work=$(mktemp -d /run/wg-underlay.XXXXXXXX)
cp -a /etc "$work/etc"
mount --bind "$work/etc" /etc
mount -t tmpfs tmpfs /usr/local
mkdir -p /usr/local/bin /usr/local/lib/hestia /run/amneziawg
install -m0755 "$daemon" /usr/local/lib/hestia/amneziawg-go
install -m0755 "$tool" /usr/local/bin/awg
export PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
getent group hestia-snapshot >/dev/null || groupadd --system hestia-snapshot
install -m0750 -d -g hestia-snapshot /run/hestia-awg
install -m0700 -d /etc/hestia/awg /etc/hestia/awg/child
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ya.ru \
    -addext 'subjectAltName=DNS:ya.ru' -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1
export SSL_CERT_FILE="$work/cert.pem"
printf '\n198.19.10.10 ya.ru\n' >>/etc/hosts
# Replace only the resolver file in the private copy of /etc.
rm -f /etc/resolv.conf
printf 'nameserver 198.19.10.10\noptions timeout:1 attempts:1\n' >/etc/resolv.conf
ip link set lo up
ip netns add peer
ip -n peer link set lo up
ip -n peer addr add 198.19.10.10/32 dev lo
devices=(chosen0 chosen1 forbidden)
for idx in 0 1 2; do
    device=${devices[idx]}
    ip link add "$device" type veth peer name "remote$idx"
    ip link set "remote$idx" netns peer
    ip addr add "198.18.$idx.1/30" dev "$device"
    ip -n peer addr add "198.18.$idx.2/30" dev "remote$idx"
    ip link set "$device" up
    ip -n peer link set "remote$idx" up
    ip -n peer route replace "198.18.$idx.0/30" dev "remote$idx" src 198.19.10.10
    # Unbound sockets always have a live fallback outside the allowed list.
    metric=$((10 + idx))
    if [[ $device == forbidden ]]; then metric=1; fi
    ip route add default via "198.18.$idx.2" dev "$device" metric "$metric"
done
# Disable reverse-path filtering only in these namespaces to allow asymmetric candidate paths to the same address.
for ns in root peer; do
    sysctl_cmd=(sysctl)
    if [[ $ns == peer ]]; then sysctl_cmd=(ip netns exec peer sysctl); fi
    "${sysctl_cmd[@]}" -qw net.ipv4.conf.all.rp_filter=0
    for dev in "${devices[@]}" remote0 remote1 remote2; do
        "${sysctl_cmd[@]}" -qw "net.ipv4.conf.$dev.rp_filter=0" 2>/dev/null || :
    done
done
awg genkey >"$work/client.key"
awg pubkey <"$work/client.key" >"$work/client.pub"
awg genkey >"$work/peer.key"
awg pubkey <"$work/peer.key" >"$work/peer.pub"
ip netns exec peer /usr/local/lib/hestia/amneziawg-go -f server >"$work/server.log" 2>&1 &
server_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if ip netns exec peer awg show server public-key >/dev/null 2>&1; then break; fi
    kill -0 "$server_pid"
    sleep 0.1
done
ip netns exec peer awg set server private-key "$work/peer.key" listen-port 51820 \
    peer "$(<"$work/client.pub")" allowed-ips 10.77.0.2/32
ip -n peer addr add 10.77.0.1/32 dev server
ip -n peer link set server up
ip -n peer route add 10.77.0.2/32 dev server
ip netns exec peer python3 "$peer_fixture" child "$work/cert.pem" "$work/key.pem" &
ip netns exec peer python3 "$here/traffic.py" serve &
ip netns exec peer python3 "$here/quality.py" "$work/cert.pem" "$work/key.pem" &
cat >/etc/hestia/awg/child/profile.conf <<PROFILE
[Interface]
PrivateKey = $(<"$work/client.key")
Address = 10.77.0.2/32
DNS = 10.77.0.1
[Peer]
PublicKey = $(<"$work/peer.pub")
Endpoint = 198.19.10.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 1
PROFILE
cat >/etc/hestia/awg/child/metadata.json <<'META'
{"id":"child","group":"vpn","priority":1,"status":"ready","type":"wireguard","ipv4Address":"10.77.0.2/32","dnsIPv4":"10.77.0.1","ipv6Blocked":false,"slot":0,"underlays":["preferred","backup"]}
META
cat >/etc/hestia/profile.json <<'PROFILE'
{"version":2,"interfaces":[{"id":"preferred","type":"direct","bind_interface":"chosen0"},{"id":"backup","type":"direct","bind_interface":"chosen1"}],"connectors":[{"id":"child","type":"wireguard","group":"vpn","priority":1,"ipv6Blocked":false,"status":"ready","underlays":["preferred","backup"]}],"groups":[{"id":"uplinks","exits":["preferred","backup"]},{"id":"vpn","exits":["child"]}],"lists":[],"healthy":{"preferred":true,"backup":true,"child":true},"socks_port":1080}
PROFILE
trial_filter='udp dst port 51820 and udp[4:2] = 792'
if [[ ${6:-} == --awg-padding ]]; then
    cat >"$work/server.conf" <<SERVER
[Interface]
PrivateKey = $(<"$work/peer.key")
ListenPort = 51820
ContentPaddingAddition = 7-23
RandomTrailers = on
[Peer]
PublicKey = $(<"$work/client.pub")
AllowedIPs = 10.77.0.2/32
SERVER
    ip netns exec peer awg setconf server "$work/server.conf"
    sed -i '/^PrivateKey/a ContentPaddingAddition = 7-23\nRandomTrailers = on' /etc/hestia/awg/child/profile.conf
    sed -i 's/"type":"wireguard"/"type":"amneziawg"/g' /etc/hestia/awg/child/metadata.json /etc/hestia/profile.json
    # 713 payload + 28 inner headers + 32 WG + 8 UDP, then 0–23 bytes of optional padding.
    trial_filter='udp dst port 51820 and udp[4:2] >= 781 and udp[4:2] <= 804'
    echo "AmneziaWG peers configured with ContentPaddingAddition=7-23 and RandomTrailers=on"
fi
if [[ ${6:-} == --native-parent ]]; then
    awg genkey >"$work/parent.client.key"
    awg pubkey <"$work/parent.client.key" >"$work/parent.client.pub"
    awg genkey >"$work/parent.server.key"
    awg pubkey <"$work/parent.server.key" >"$work/parent.server.pub"
    ip netns exec peer /usr/local/lib/hestia/amneziawg-go -f parent >"$work/parent.log" 2>&1 &
    parent_pid=$!
    for ((attempt = 0; attempt < 100; attempt++)); do
        if ip netns exec peer awg show parent public-key >/dev/null 2>&1; then break; fi
        kill -0 "$parent_pid"
        sleep 0.1
    done
    ip netns exec peer awg set parent private-key "$work/parent.server.key" listen-port 51821 \
        peer "$(<"$work/parent.client.pub")" allowed-ips 10.91.0.2/32
    ip -n peer addr add 10.91.0.1/32 dev parent
    ip -n peer link set parent up
    ip -n peer route add 10.91.0.2/32 dev parent src 198.19.10.10
    ip netns exec peer iptables -t nat -A POSTROUTING -p udp --sport 51821 -o remote0 -j SNAT --to-source 198.18.0.2
    cat >/etc/hestia/parent.conf <<PARENT
[Interface]
Address = 10.91.0.2/32
PrivateKey = $(<"$work/parent.client.key")
DNS = 198.19.10.10
[Peer]
PublicKey = $(<"$work/parent.server.pub")
Endpoint = 198.18.0.2:51821
AllowedIPs = 0.0.0.0/0
PARENT
    sed -i 's/"type":"direct","bind_interface":"chosen0"/"type":"wireguard","config_file":"parent.conf"/' /etc/hestia/profile.json
fi
echo "kernel=$(uname -r); unmarked route to peer: $(ip route get 198.19.10.10 | head -1)"
echo "hestia sha256=$(sha256sum "$hestia" | cut -d' ' -f1)"
before=$(ip -4 route show table main)
for device in "${devices[@]}"; do
    sniffer=(tcpdump)
    capture_device=$device
    if [[ ${6:-} == --native-parent && $device == chosen0 ]]; then
        # Observe the child UDP inside the remote parent TUN, after authenticated decryption.
        sniffer=(ip netns exec peer tcpdump)
        capture_device=parent
    fi
    "${sniffer[@]}" -n -Z root --immediate-mode -U -s 100 -i "$capture_device" -w "$work/$device.pcap" 'dst host 198.19.10.10 and udp' 2>"$work/$device.capture" &
    for ((attempt = 0; attempt < 50; attempt++)); do
        if [[ -e $work/$device.capture ]] && grep -q 'listening on' "$work/$device.capture"; then break; fi
        sleep 0.1
    done
    grep -q 'listening on' "$work/$device.capture"
done

# packet_count counts only fixed-size application trials on one carrier or the requested capture filter.
packet_count() {
    tcpdump -nn -r "$work/$1.pcap" "${2:-$trial_filter}" 2>/dev/null | wc -l
}

# path_trial proves delivery of a fresh application nonce and checks that its encrypted packet used this one device.
path_trial() {
    local label=$1 intended=$2 deadline=$((SECONDS + 115)) device changed active=
    case $intended in chosen0) active=preferred ;; chosen1) active=backup ;; esac
    local -A start
    while ((SECONDS < deadline)); do
        if ! kill -0 "$runtime_pid" 2>/dev/null; then
            cat "$work/runtime.log" >&2
            return 1
        fi
        for device in "${devices[@]}"; do start[$device]=$(packet_count "$device"); done
        if python3 "$here/traffic.py" trial --label "$label"; then
            changed=0
            for ((attempt = 0; attempt < 25; attempt++)); do
                if (($(packet_count "$intended") > start[$intended])); then
                    changed=1
                    break
                fi
                sleep 0.04
            done
            if ((changed)); then
                for device in "${devices[@]}"; do
                    if [[ $device != "$intended" ]]; then
                        if (($(packet_count "$device") != start[$device])); then changed=0; fi
                    fi
                done
                if [[ -n $active ]] && ! grep -Fqs '"activeUnderlay":"'"$active"'"' /run/hestia-awg/health.json.child; then changed=0; fi
                if ((changed)); then
                    echo "$label: echo matched; encrypted trial via $intended only"
                    return 0
                fi
            fi
        fi
        sleep 0.4
    done
    echo "$label: timed out waiting for inner echo on $intended" >&2
    for device in "${devices[@]}"; do echo "$device frames: $(packet_count "$device" 'udp dst port 51820')" >&2; done
    tail -20 "$work/runtime.log" >&2
    return 1
}

# impair imposes receive-path loss at the remote endpoint while the local links and routes stay up.
impair() {
    ip netns exec peer iptables "$1" INPUT -i "remote$2" -j DROP
}

if [[ ${6:-} == --automatic-control ]]; then
    sed -i 's/,"underlays":\["preferred","backup"\]//g' /etc/hestia/{profile.json,awg/child/metadata.json}
fi
"$hestia" -awg-runtime child >"$work/runtime.log" 2>&1 &
runtime_pid=$!
if [[ ${6:-} != --automatic-control ]]; then
    # Model boot: start the manual runtime first; the backend is permitted to start once both family guards exist.
    for ((attempt = 0; attempt < 100; attempt++)); do
        if ! kill -0 "$runtime_pid" 2>/dev/null; then
            cat "$work/runtime.log" >&2
            exit 1
        fi
        if [[ -s /run/hestia-awg/routes.json.child ]] && ip -4 route show table 202 2>/dev/null | grep -q 'unreachable default' &&
            ip -6 route show table 202 2>/dev/null | grep -q 'unreachable default' &&
            ip -4 rule show | grep -q 'fwmark 0x202.*lookup 202' && ip -6 rule show | grep -q 'fwmark 0x202.*lookup 202' &&
            ip -4 rule show | grep -q 'fwmark 0x51000.*unreachable' && ip -6 rule show | grep -q 'fwmark 0x51000.*unreachable'; then break; fi
        sleep 0.1
    done
    ((attempt < 100))
    [[ ! -e /run/hestia-awg/ready.child && ! -e /run/hestia-awg/health.json.child ]]
    (($(packet_count forbidden 'udp dst port 51820') == 0))
    if ip -4 route get 198.19.10.10 mark 0x51000 >/dev/null 2>&1 || ip -6 route get 2001:db8::1 mark 0x51000 >/dev/null 2>&1; then
        echo "WireGuard outer socket has nonlocal route" >&2
        exit 1
    fi
    ip -4 route get 127.0.0.1 mark 0x51000 >/dev/null
    echo "guarded startup: child service running with IPv4 and IPv6 guards; readiness withheld before backend"
    python3 -I "$compiler" /etc/hestia/profile.json /etc/hestia
    "$singbox" check -c /etc/hestia/sing-box.json
    "$singbox" run -c /etc/hestia/sing-box.json >"$work/singbox.log" 2>&1 &
    router_pid=$!
    for ((attempt = 0; attempt < 100; attempt++)); do
        if curl -fsS --max-time 1 --noproxy '*' http://127.0.0.1:9090/proxies/preferred >/dev/null 2>&1; then break; fi
        if ! kill -0 "$router_pid" 2>/dev/null; then
            cat "$work/singbox.log" >&2
            exit 1
        fi
        sleep 0.1
    done
    for candidate in preferred backup; do
        code=$(curl --noproxy '*' -sS --max-time 8 -w '%{http_code}' -o "$work/delay.json" \
            "http://127.0.0.1:9090/proxies/$candidate/delay?url=https%3A%2F%2Fya.ru%2F&timeout=4000")
        if [[ $code != 200 ]]; then
            cat "$work/delay.json" "$work/singbox.log" >&2
            exit 1
        fi
        echo "quality preflight $candidate: HTTP $code $(cat "$work/delay.json")"
    done
fi
if [[ ${6:-} == --automatic-control ]]; then
    path_trial automatic-control forbidden
    exit 0
fi
path_trial initial chosen0
if [[ ${6:-} == --native-parent ]]; then
    ip netns exec peer awg show parent latest-handshakes | awk 'NF == 2 && $2 > 0 {ok=1} END {exit !ok}'
    echo "preferred: independent native WireGuard handshake and child outer UDP observed after decryption"
fi
if [[ ${6:-} == --udp-loss ]]; then
    ip netns exec peer iptables -I INPUT -i remote0 -p udp --dport 51820 -j DROP
    # TLS through the preferred carrier remains usable while the WireGuard peer cannot receive its UDP packets.
    code=$(curl --noproxy '*' -sS --max-time 6 -w '%{http_code}' -o "$work/https-up.json" \
        'http://127.0.0.1:9090/proxies/preferred/delay?url=https%3A%2F%2Fya.ru%2F&timeout=4000')
    [[ $code == 200 ]]
    echo "preferred HTTPS healthy, only WireGuard UDP dropped"
    path_trial udp-only-failover chosen1
    on_backup=$(packet_count chosen1)
    deadline=$((SECONDS + 65))
    samples=0
    while ((SECONDS < deadline)); do
        if ! python3 "$here/traffic.py" trial --label backup-stability --timeout 1; then
            echo "backup lost application traffic during UDP-only primary failure after $samples stable trials" >&2
            exit 1
        fi
        grep -qs '"activeUnderlay":"backup"' /run/hestia-awg/health.json.child || {
            echo "working backup prematurely withdrawn" >&2
            exit 1
        }
        samples=$((samples + 1))
        sleep 0.4
    done
    (($(packet_count chosen1) >= on_backup + samples))
    echo "backup stable through 65s of persistent selective UDP loss ($samples fresh echoes), all trials captured on verified backup"
    tc qdisc add dev chosen0 root netem delay 120ms
    echo "restoring preferred with an additional 120ms of outbound latency; backup stays faster"
    ip netns exec peer iptables -D INPUT -i remote0 -p udp --dport 51820 -j DROP
    path_trial recovered-peer chosen0
    exit 0
fi
impair -I 0
path_trial failed-primary chosen1
impair -D 0
path_trial recovered-primary chosen0
impair -I 0
impair -I 1
for ((attempt = 0; attempt < 10; attempt++)); do
    if python3 "$here/traffic.py" trial --timeout 0.6 --label denied; then
        echo 'Unexpected echo with both carriers down' >&2
        exit 1
    fi
    sleep 0.3
done
# Prove the third default path actually works for an unmarked packet, while checking every outer WG packet for leakage.
python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"control", ("198.19.10.10", 15999))'
for ((attempt = 0; attempt < 50; attempt++)); do
    if (($(packet_count forbidden 'udp dst port 15999') == 1)); then break; fi
    sleep 0.1
done
(($(packet_count forbidden 'udp dst port 15999') == 1))
(($(packet_count forbidden 'udp dst port 51820') == 0))
echo "all selected paths down: no echo; 0 WireGuard packets on forbidden; 1 unmarked control packet captured"
impair -D 1
path_trial restored-backup chosen1
[[ $(ip -4 route show table main) == "$before" ]]
echo "main routing table unchanged"
