#!/usr/bin/env bash
# Install scheme 3 on a dedicated, clean Debian Lima guest. Never print private keys.
set +x
set -euo pipefail
umask 077
assets=$(cd -- "$(dirname -- "$0")" && pwd)
state=/etc/hestia-scheme3
wgconf=/etc/wireguard/wg-keenetic.conf

# fail exits before continuing with ambiguous ownership or environment.
fail() {
    echo "$*" >&2
    exit 1
}

[[ $EUID == 0 && -f /etc/debian_version && -d /run/systemd/system ]] || fail 'Run as root inside the Debian systemd guest.'
[[ $(hostname -s) != *hestia-stage1* ]] || fail 'Refusing the personal VM.'
for cmd in wg wg-quick ip iptables ss sysctl systemctl flock; do
    command -v "$cmd" >/dev/null || fail "Missing dependency: $cmd"
done
exec 9>/run/hestia-scheme3.lock
flock -n 9 || fail 'Another installer is running.'
for binary in /usr/local/bin/{sing-box,hestia}; do
    [[ -x $binary ]] || fail "Missing binary: $binary"
done
lan=$(ip -4 -o addr show dev lima0 scope global | awk '$4 ~ /^192\.168\.1\.[0-9]+\/24$/ {sub("/24","",$4); print $4}')
[[ $lan =~ ^192\.168\.1\.[0-9]+$ && $lan != 192.168.1.133 ]] || fail 'Expected a single lab LAN address on lima0 (not the personal VM).'
route=$(ip -4 route get 1.1.1.1)
[[ $route == *'via 192.168.1.1 dev lima0 '* ]] || fail 'The default IPv4 route must use Keenetic via lima0.'

policy_unit=/etc/systemd/system/hestia-scheme3-policy.service
wg_dropin=/etc/systemd/system/wg-quick@wg-keenetic.service.d
targets=("$policy_unit" "$wg_dropin/90-hestia-policy.conf" "$wgconf" /etc/hestia/{sing-box,snapshot}.json /etc/systemd/system/{hestia-sing-box,hestia}.service /etc/sysctl.d/90-hestia-forward.conf)
if [[ ! -e $state && ! -L $state ]]; then
    for target in "${targets[@]}"; do
        [[ ! -e $target && ! -L $target ]] || fail "Unmanaged file: $target"
    done
    for unit in hestia.service hestia-sing-box.service hestia-scheme3-policy.service; do
        ! systemctl cat "$unit" >/dev/null 2>&1 || fail "Unmanaged unit: $unit"
    done
    for dev in wg-keenetic hestia0; do
        ! ip link show dev "$dev" >/dev/null 2>&1 || fail "Unmanaged device: $dev"
    done
    [[ -z $(ss -Hlun 'sport = :51827') ]] || fail 'UDP port 51827 already in use.'
    bash "$assets/guest-network.sh" preflight
    tmp=$(mktemp -d /etc/.hestia-scheme3.XXXXXXXX)
    trap 'rm -rf -- "$tmp"' EXIT
    wg genkey >"$tmp/guest.key"
    wg genkey >"$tmp/keenetic.key"
    echo scheme3-v1 >"$tmp/owner"
    mv -T -- "$tmp" "$state"
fi
[[ ! -L $state && $(cat "$state/owner") == scheme3-v1 ]] || fail "Unmanaged directory: $state"
for key in "$state"/{guest,keenetic}.key; do
    [[ -f $key && ! -L $key && $(stat -c '%u:%a' "$key") == 0:600 ]] || fail "Missing or unsafe key: $key"
done

# managed installs a new file or accepts an identical one, rejecting local edits.
managed() {
    local src=$1 dest=$2 mode=$3 group=${4:-root} gid
    gid=$(getent group "$group" | cut -d: -f3)
    if [[ -e $dest || -L $dest ]]; then
        [[ ! -L $dest && -f $dest ]] || fail "Unmanaged file: $dest"
        cmp -s "$src" "$dest" || fail "Existing configuration differs: $dest"
        [[ $(stat -c '%u:%g:%a' "$dest") == "0:${gid}:${mode#0}" ]] || fail "Unsafe ownership or permissions: $dest"
    else
        install -o root -g "$group" -m "$mode" "$src" "$dest"
    fi
}

scratch=$(mktemp -d "$state/.install.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
guestpub=$(wg pubkey <"$state/guest.key")
peerpub=$(wg pubkey <"$state/keenetic.key")
cat >"$scratch/wg.conf" <<WG
[Interface]
Address = 10.253.241.2/30
ListenPort = 51827
PrivateKey = $(cat "$state/guest.key")
Table = off

[Peer]
PublicKey = $peerpub
AllowedIPs = 10.253.241.1/32, 192.168.1.0/24
WG
cat >"$scratch/keenetic.conf" <<WG
[Interface]
Address = 10.253.241.1/30
PrivateKey = $(cat "$state/keenetic.key")

[Peer]
PublicKey = $guestpub
Endpoint = $lan:51827
AllowedIPs = 10.253.241.2/32
PersistentKeepalive = 25
WG
echo 'net.ipv4.ip_forward=1' >"$scratch/sysctl"
mkdir -p /etc/wireguard
if [[ ! -d /etc/hestia ]]; then install -d -m 0755 /etc/hestia; fi
if [[ ! -d $wg_dropin ]]; then install -d -m 0755 "$wg_dropin"; fi
managed "$assets/guest-policy.service" "$policy_unit" 0644
managed "$assets/guest-wg-policy.conf" "$wg_dropin/90-hestia-policy.conf" 0644
managed "$assets/guest-network.sh" "$state/network" 0755
managed "$scratch/wg.conf" "$wgconf" 0600
managed "$scratch/keenetic.conf" "$state/hestia-keenetic.conf" 0600
managed "$assets/guest-sing-box.json" /etc/hestia/sing-box.json 0644
managed "$assets/guest-snapshot.json" /etc/hestia/snapshot.json 0640 hestia-snapshot
managed "$scratch/sysctl" /etc/sysctl.d/90-hestia-forward.conf 0644
managed "$assets/guest-sing-box.service" /etc/systemd/system/hestia-sing-box.service 0644
managed "$assets/guest-hestia.service" /etc/systemd/system/hestia.service 0644
python3 -I "$assets/adopt-profile.py" adopt /etc/hestia "$assets/guest-profile.json" /usr/local/lib/hestia/profile.py
chown root:root /etc/hestia/sing-box.json
chmod 0600 /etc/hestia/sing-box.json
/usr/local/bin/sing-box check -c /etc/hestia/sing-box.json
systemctl daemon-reload
systemctl enable --now hestia-binding-watch.path
systemctl enable --now wg-quick@wg-keenetic.service hestia-sing-box.service hestia.service
sysctl -w net.ipv4.ip_forward=1 >/dev/null
systemctl is-active --quiet wg-quick@wg-keenetic.service
systemctl is-active --quiet hestia-sing-box.service
systemctl is-active --quiet hestia.service
echo "Scheme 3 guest: $lan; private router profile: $state/hestia-keenetic.conf"
