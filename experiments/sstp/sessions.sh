# Source in a root-only disposable guest lab after validating OUT.
modprobe ppp_generic
modprobe ppp_async
[[ -c /dev/ppp ]]
RUN=$(mktemp -d)
namespaces=()
caps=()
cleanup() {
    local ns pid
    for ns in "${namespaces[@]}"; do
        for pid in $(ip netns pids "$ns"); do kill "$pid" 2>/dev/null || true; done
    done
    for ns in "${namespaces[@]}"; do ip netns del "$ns" || true; done
    rm -rf -- "$RUN"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
target=203.0.113.77
c() { ip netns exec "hs-c$1-$$" "${@:2}"; }
s() { ip netns exec "hs-s$1-$$" "${@:2}"; }
start_peer() {
    local i=$1 who ns pass
    for who in c s; do
        ns="hs-$who$i-$$"; ip netns add "$ns"; namespaces+=("$ns"); ip -n "$ns" link set lo up
    done
    ip -n "hs-c$i-$$" link add wan type veth peer name lan netns "hs-s$i-$$"
    c "$i" ip addr add "10.83.$i.1/30" dev wan
    s "$i" ip addr add "10.83.$i.2/30" dev lan
    c "$i" ip link set wan up
    s "$i" ip link set lan up
    s "$i" ip addr add "$target/32" dev lo
    openssl req -x509 -newkey rsa:2048 -noenc -days 1 -subj "/CN=10.83.$i.2" \
      -addext "subjectAltName=IP:10.83.$i.2" -keyout "$RUN/$i.key" -out "$RUN/$i.crt" 2>/dev/null
    pass=$(openssl rand -hex 24)
    printf 'lab * %s 172.16.3.33\n' "$pass" > "$RUN/$i.secrets"
    cat > "$RUN/$i.conf" <<CFG
[modules]
log_file
sstp
auth_mschap_v2
chap-secrets
[core]
thread-count=2
[common]
seq-file=$RUN/$i.seq
[ppp]
ipv4=require
ipv6=deny
mtu=1400
mru=1400
ccp=0
[sstp]
bind=10.83.$i.2
port=443
accept=ssl
ssl-pemfile=$RUN/$i.crt
ssl-keyfile=$RUN/$i.key
ifname=sstp%d
[client-ip-range]
10.83.$i.0/30
[chap-secrets]
chap-secrets=$RUN/$i.secrets
gw-ip-address=172.16.3.1
[log]
log-file=$RUN/$i.log
level=5
CFG
    s "$i" accel-pppd -c "$RUN/$i.conf" > "$RUN/a$i.out" 2>&1 &
    for _ in {1..100}; do s "$i" ss -lnt | grep -q ':443 ' && break; sleep .05; done
    s "$i" ss -lnt | grep -q ':443 ' || { cat "$RUN/a$i.out"; exit 1; }
    # Distinct pppd pid files / callback sockets despite shared guest filesystem.
    ip netns exec "hs-c$i-$$" sstpc --ca-cert "$RUN/$i.crt" --ipparam "hs-$i-$$" \
      --user lab --password "$pass" --log-stderr "10.83.$i.2" \
      noauth noipdefault nobsdcomp nodeflate noccp noipv6 refuse-pap refuse-chap refuse-mschap \
      refuse-eap ipparam "hs-$i-$$" linkname "hs-$i-$$" ifname "hs$i" \
      > "$RUN/c$i.out" 2>&1 &
    client_pids[$i]=$!
    for _ in {1..180}; do c "$i" ip -4 -o addr show | grep -q 'inet 172.16.3.33 peer' && break; sleep .1; done
    if ! c "$i" ip -4 -o addr show | grep -q 'inet 172.16.3.33 peer'; then
        echo "FI$i: PPP did not negotiate the expected address" >&2
        grep -Ei "error|fail|not found|unrecognized|unknown option|unable" "$RUN/c$i.out" | cut -c1-180 | head -8 >&2 || true
        exit 1
    fi
    # Export only affirmative stage names (never raw PPP auth fields).
    s "$i" ss -nt | grep -q "10.83.$i.2:443" || exit 1
    { echo "SSTP server endpoint=10.83.$i.2:443 established"
      echo "Client peer certificate pinned to ephemeral FI$i certificate"
      c "$i" ip -4 addr show "hs$i" | sed -n '/inet 172.16.3.33 peer /p'
    } > "$OUT/FI$i-session.txt"
    c "$i" ip route add "$target/32" dev "hs$i"
}
