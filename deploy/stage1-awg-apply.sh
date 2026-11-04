#!/usr/bin/env bash
# Apply a prebuilt Hestia/AWG bundle only to the existing managed stage1 guest.
set -euo pipefail
umask 077
[[ $# == 1 && $EUID == 0 ]] || {
    echo "Usage: sudo bash stage1-awg-apply.sh PACKAGE_DIRECTORY" >&2
    exit 2
}
bundle=$(realpath "$1")
[[ -d $bundle && ! -L $1 ]] || {
    echo "Unsafe package directory" >&2
    exit 1
}
[[ $(hostname -s) == lima-hestia-stage1 ]] || {
    echo "Refusing a guest other than lima-hestia-stage1" >&2
    exit 1
}
ip -4 -o addr show dev lima0 scope global | awk '$4 ~ /^192\.168\.1\.133\// { found=1 } END { exit !found }' || {
    echo "Refusing a guest without 192.168.1.133 on lima0" >&2
    exit 1
}
[[ -f /etc/hestia/.installer-managed && ! -L /etc/hestia/.installer-managed &&
    $(stat -c '%u:%a' /etc/hestia/.installer-managed) == 0:600 &&
    $(cat /etc/hestia/.installer-managed) == 1 ]] || {
    echo "Refusing an unmanaged Hestia installation" >&2
    exit 1
}
[[ ! -e /etc/hestia/.binding-pending && ! -L /etc/hestia/.binding-pending ]] || {
    echo "Recover the pending binding transaction before updating" >&2
    exit 1
}
[[ -e /run/hestia-install.lock && ! -L /run/hestia-install.lock &&
    $(stat -c '%u' /run/hestia-install.lock) == 0 ]] || {
    echo "The managed installer lock is missing or unsafe" >&2
    exit 1
}
exec 9</run/hestia-install.lock
flock -n 9 || {
    echo "Another Hestia transaction is running" >&2
    exit 1
}
for service in wg-quick@wg-keenetic.service hestia-sing-box.service hestia.service hestia-panel.service; do
    [[ $(systemctl is-active "$service" 2>/dev/null || :) == active ]] || {
        echo "Required service is not active: $service" >&2
        exit 1
    }
done
[[ $(systemctl is-active hestia-awg.service 2>/dev/null || :) != active ]] || {
    echo "Refusing to replace an active AWG runtime" >&2
    exit 1
}
[[ -f /etc/hestia/snapshot.json && ! -L /etc/hestia/snapshot.json &&
    -f /etc/hestia/sing-box.json && ! -L /etc/hestia/sing-box.json &&
    -f /etc/hestia/profile.json && ! -L /etc/hestia/profile.json ]] || {
    echo "Managed profile files are missing or unsafe" >&2
    exit 1
}
[[ -f /etc/wireguard/wg-keenetic.conf && ! -L /etc/wireguard/wg-keenetic.conf &&
    $(stat -c '%u' /etc/wireguard/wg-keenetic.conf) == 0 ]] || {
    echo "wg-keenetic config is missing or unsafe" >&2
    exit 1
}
getent group hestia-snapshot >/dev/null || {
    echo "hestia-snapshot group is missing" >&2
    exit 1
}
getent passwd hestia-panel >/dev/null || {
    echo "Static hestia-panel account is missing" >&2
    exit 1
}
[[ $(getent passwd hestia-panel | cut -d: -f7) == /usr/sbin/nologin ]] || {
    echo "hestia-panel is not a locked service account" >&2
    exit 1
}
[[ -f /etc/systemd/system/hestia-panel.service && ! -L /etc/systemd/system/hestia-panel.service &&
    $(systemctl show hestia-panel.service -p FragmentPath --value) == /etc/systemd/system/hestia-panel.service ]] || {
    echo "Expected managed hestia-panel.service was not found" >&2
    exit 1
}
grep -Fq -- '-listen 192.168.1.133:8080' /etc/systemd/system/hestia-panel.service || {
    echo "The current panel listener differs from stage1" >&2
    exit 1
}
[[ $(systemctl is-enabled hestia-panel.service 2>/dev/null || :) == enabled ]] || {
    echo "The panel unit must already be enabled" >&2
    exit 1
}

(cd "$bundle" && sha256sum --check SHA256SUMS)
"$bundle/amneziawg-go" --version | grep -F "amneziawg-go v3.1.20260828" >/dev/null || {
    echo "The bundled AmneziaWG runtime version is unexpected" >&2
    exit 1
}
python3 -I "$bundle/profile.py" --validate-managed /etc/hestia
python3 -I -c 'import json,sys; p=json.load(open(sys.argv[1])); raise SystemExit(1 if any(c.get("status")=="ready" for c in p.get("connectors", [])) else 0)' /etc/hestia/profile.json || {
    echo "Refusing an update while an AWG connector is marked ready" >&2
    exit 1
}
if ! command -v make >/dev/null || ! command -v gcc >/dev/null; then
    echo "The existing guest needs make and gcc to build the pinned awg tools" >&2
    exit 1
fi
mkdir -m 0700 "$bundle/awg-tools-build"
tar -xf "$bundle/amneziawg-tools-source.tar" -C "$bundle/awg-tools-build"
make -C "$bundle/awg-tools-build/src"
"$bundle/awg-tools-build/src/wg" --version | grep -F "v3.1.20260812" >/dev/null || {
    echo "The built awg utility version is unexpected" >&2
    exit 1
}
visudo -cf "$bundle/hestia-awg.sudoers" >/dev/null

# require_root_file verifies an existing target before the update replaces it; it never follows symlinks.
require_root_file() {
    local path=$1
    [[ -f $path && ! -L $path && $(stat -c '%u' "$path") == 0 ]] || {
        echo "Unsafe or missing managed file: $path" >&2
        return 1
    }
}

config_digest() {
    sha256sum /etc/hestia/snapshot.json /etc/hestia/sing-box.json \
        /etc/hestia/profile.json /etc/wireguard/wg-keenetic.conf
}

backup=/var/backups/hestia-stage1-awg-$(date -u +%Y%m%dT%H%M%SZ)
install -d -o root -g root -m 0700 "$backup"
for path in /usr/local/bin/hestia /usr/local/bin/hestia-panel \
    /usr/local/lib/hestia/profile.py /etc/systemd/system/hestia.service \
    /etc/systemd/system/hestia-panel.service; do
    if [[ -e $path || -L $path ]]; then
        require_root_file "$path"
        cp -p -- "$path" "$backup/$(basename "$path").previous"
    fi
done
if [[ -L /usr/local/share/hestia-panel/current ]]; then
    cp -a /usr/local/share/hestia-panel/current "$backup/panel-assets.previous"
fi

routes_before=$(mktemp "$bundle/routes-before.XXXXXX")
hashes_before=$(mktemp "$bundle/hashes-before.XXXXXX")
{
    printf 'IPv4 default routes\n'
    ip -4 route show default
    printf 'IPv6 default routes\n'
    ip -6 route show default
} >"$routes_before"
config_digest >"$hashes_before"

install -d -o root -g root -m 0755 /usr/local/bin /usr/local/lib/hestia \
    /usr/local/share/hestia-panel/releases /etc/systemd/system /etc/tmpfiles.d /etc/sudoers.d
if [[ -e /etc/hestia/awg || -L /etc/hestia/awg ]]; then
    [[ -d /etc/hestia/awg && ! -L /etc/hestia/awg && $(stat -c '%u:%a' /etc/hestia/awg) == 0:700 ]] || {
        echo "Unsafe AWG profile store" >&2
        exit 1
    }
else
    install -d -o root -g root -m 0700 /etc/hestia/awg
fi

asset_id=$(python3 -I -c 'import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]); files=sorted(x for x in p.rglob("*") if x.is_file()); h=hashlib.sha256(); [h.update(x.relative_to(p).as_posix().encode()+b"\0"+hashlib.sha256(x.read_bytes()).digest()) for x in files]; print(h.hexdigest()[:20])' "$bundle/browser")
asset_release=/usr/local/share/hestia-panel/releases/$asset_id
if [[ ! -d $asset_release ]]; then
    install -d -o root -g root -m 0755 "$asset_release"
    cp -R "$bundle/browser/." "$asset_release/"
    chown -R root:root "$asset_release"
    chmod -R a-w,go+rX "$asset_release"
fi
ln -sfn "releases/$asset_id" /usr/local/share/hestia-panel/current.next
mv -fT /usr/local/share/hestia-panel/current.next /usr/local/share/hestia-panel/current
install -o root -g root -m 0755 "$bundle/hestia" /usr/local/bin/hestia.next
mv -fT /usr/local/bin/hestia.next /usr/local/bin/hestia
install -o root -g root -m 0755 "$bundle/hestia-panel" /usr/local/bin/hestia-panel.next
mv -fT /usr/local/bin/hestia-panel.next /usr/local/bin/hestia-panel
install -o root -g root -m 0644 "$bundle/profile.py" /usr/local/lib/hestia/profile.py.next
mv -fT /usr/local/lib/hestia/profile.py.next /usr/local/lib/hestia/profile.py
install -o root -g root -m 0755 "$bundle/amneziawg-go" /usr/local/lib/hestia/amneziawg-go.next
mv -fT /usr/local/lib/hestia/amneziawg-go.next /usr/local/lib/hestia/amneziawg-go
install -o root -g root -m 0755 "$bundle/awg-tools-build/src/wg" /usr/local/bin/awg.next
mv -fT /usr/local/bin/awg.next /usr/local/bin/awg
printf 'amneziawg-go=3.1.20260828 commit=b5928efb6ca19f0153958460c3d141f04abc5c2e\namneziawg-tools=3.1.20260812 commit=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843\n' >"$bundle/awg-version"
install -o root -g root -m 0600 "$bundle/awg-version" /etc/hestia/.awg-runtime-version
install -o root -g root -m 0644 "$bundle/hestia-awg.service" /etc/systemd/system/hestia-awg.service
install -o root -g root -m 0644 "$bundle/hestia-awg.conf" /etc/tmpfiles.d/hestia-awg.conf
install -o root -g root -m 0440 "$bundle/hestia-awg.sudoers" /etc/sudoers.d/hestia-awg
sed 's|@PANEL_LISTEN@|192.168.1.133:8080|g' "$bundle/hestia-panel.service.in" >"$bundle/hestia-panel.service"
install -o root -g root -m 0644 "$bundle/hestia-panel.service" /etc/systemd/system/hestia-panel.service
install -o root -g root -m 0644 "$bundle/hestia.service" /etc/systemd/system/hestia.service
visudo -cf /etc/sudoers.d/hestia-awg >/dev/null
systemctl daemon-reload
systemd-tmpfiles --create /etc/tmpfiles.d/hestia-awg.conf
/usr/local/bin/hestia -check -config /etc/hestia/snapshot.json
/usr/local/lib/hestia/sing-box check -c /etc/hestia/sing-box.json >/dev/null
python3 -I /usr/local/lib/hestia/profile.py --validate-managed /etc/hestia
systemctl restart hestia.service hestia-panel.service
systemctl is-active --quiet wg-quick@wg-keenetic.service
systemctl is-active --quiet hestia-sing-box.service hestia.service hestia-panel.service
curl --noproxy '*' --fail --silent --show-error --max-time 5 \
    http://192.168.1.133:8080/ -o "$bundle/panel-check.html"
grep -q '<html' "$bundle/panel-check.html" || {
    echo "Panel did not serve its frontend" >&2
    exit 1
}
{
    printf 'IPv4 default routes\n'
    ip -4 route show default
    printf 'IPv6 default routes\n'
    ip -6 route show default
} >"$bundle/routes-after"
config_digest >"$bundle/hashes-after"
cmp -s "$routes_before" "$bundle/routes-after" || {
    echo "Main default routes changed; inspect the deployment backup before continuing" >&2
    exit 1
}
cmp -s "$hashes_before" "$bundle/hashes-after" || {
    echo "WG-keenetic or profile/backend/snapshot bytes changed unexpectedly" >&2
    exit 1
}
echo "Stage1 package is installed. Backup of replaced application/service files: $backup"
