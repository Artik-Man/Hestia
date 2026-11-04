#!/usr/bin/env bash
# Shared WireGuard receiver fixture for the isolated Hestia VM.
# peer creates a private uplink, tunnel, DNS server and labeled HTTP target in one namespace.
peer() {
    local n=$1 label=$2 work=$3 name="binding-$2" instance="$3/$2" client_key server_key
    mkdir -p "$instance/www"
    wg genkey >"$instance/client.key"
    wg genkey >"$instance/server.key"
    client_key=$(wg pubkey <"$instance/client.key")
    server_key=$(wg pubkey <"$instance/server.key")
    ip netns add "$name"
    ip link add "bind$n" type veth peer name uplink netns "$name"
    ip addr add "10.240.$n.1/30" dev "bind$n"
    ip link set "bind$n" up
    ip -n "$name" addr add "10.240.$n.2/30" dev uplink
    ip -n "$name" link set uplink up
    ip -n "$name" link set lo up
    ip -n "$name" addr add 198.18.42.42/32 dev lo
    ip -n "$name" link add tunnel type wireguard
    ip netns exec "$name" wg set tunnel listen-port 51820 private-key "$instance/server.key" peer "$client_key" allowed-ips "10.211.$n.2/32"
    ip -n "$name" addr add "10.211.$n.1/24" dev tunnel
    ip -n "$name" link set tunnel up
    printf '%s\n' "$label" >"$instance/www/probe"
    systemd-run --quiet --unit="binding-$label-dns" ip netns exec "$name" \
        dnsmasq --keep-in-foreground --conf-file=/dev/null --no-hosts --no-resolv --bind-interfaces \
        --listen-address="10.211.$n.1" --address=/lab.test/198.18.42.42
    systemd-run --quiet --unit="binding-$label-http" ip netns exec "$name" \
        python3 -m http.server 18080 --bind 198.18.42.42 --directory "$instance/www"
    {
        printf '[Interface]\nAddress = 10.211.%s.2/32\nDNS = 10.211.%s.1\nPrivateKey = ' "$n" "$n"
        cat "$instance/client.key"
        printf '\n[Peer]\nPublicKey = %s\nEndpoint = 10.240.%s.2:51820\nAllowedIPs = 0.0.0.0/0\n' "$server_key" "$n"
    } >"$work/$label.conf"
}
