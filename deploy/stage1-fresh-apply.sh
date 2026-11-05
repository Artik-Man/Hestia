#!/usr/bin/env bash
# Replace Hestia application data with the repository profile on the named stage1 gateway.
set -euo pipefail
umask 077
[[ $# == 1 && $EUID == 0 && $1 =~ ^/tmp/hestia-stage1-awg\.[a-zA-Z0-9]+$ ]]
[[ $(stat -c '%u:%a' "$1") == 0:700 ]]
cd "$1"
[[ $(hostname -s) == lima-hestia-stage1 ]]
ip -4 -o addr show dev lima0 scope global | grep -Eq " inet 192\.168\.1\.133/"
exec 8>/run/hestia-stage1-fresh.lock
flock -n 8 || {
    echo "Another stage1 installation is running" >&2
    exit 1
}
sha256sum -c SHA256SUMS
# shellcheck source=stage1-backend-credential.sh
source ./stage1-backend-credential.sh
check_backend_credential ./stage1-backend-credential.dropin || {
    echo "Unsafe or unsupported sing-box unit" >&2
    exit 1
}
mkdir tools config
tar xf amneziawg-tools-source.tar -C tools
make -C tools/src
python3 -I profile.py guest-profile.json config .
./hestia -check -config config/snapshot.json
/usr/local/bin/sing-box check -c config/sing-box.json
getent group hestia-snapshot >/dev/null || groupadd --system hestia-snapshot
id hestia-panel >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin hestia-panel
visudo -cf hestia-awg.sudoers
for unit in hestia-dns.service hestia-panel.service hestia-binding-watch.path hestia-binding-watch.service hestia.service hestia-sing-box.service hestia-awg.service; do
    if [[ $(systemctl show "$unit" -p LoadState --value) != not-found ]]; then
        systemctl stop "$unit"
    fi
done
if [[ $(systemctl is-enabled hestia-awg.service 2>/dev/null || :) == enabled ]]; then
    systemctl disable hestia-awg.service
fi
exec 9<>/run/hestia-install.lock
flock -w 30 9
systemctl stop 'hestia-awg@*.service'
# Retire explicitly owned guards before removing the files that identify them.
[[ ! -e /run/hestia-awg/routes.json && ! -L /run/hestia-awg/routes.json ]] || {
    echo "Legacy route ownership remains; fresh install stopped" >&2
    exit 1
}
awg_connection_id_pattern='^([a-z][a-z0-9-]{0,62}|[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12})$'
shopt -s nullglob
for record in /run/hestia-awg/routes.json.*; do
    id=${record##*/routes.json.}
    [[ $id =~ $awg_connection_id_pattern && ! -L $record && -f $record && $(stat -c '%u:%a:%h' "$record") == 0:600:1 ]] || exit 1
    slot=$(python3 -I -c 'import json, sys; print(int(json.load(open(sys.argv[1]))["table"]) - 202)' "$record")
    ./hestia -awg-retire "$id" "$slot"
done
shopt -u nullglob
rm -rf -- /etc/hestia /run/hestia-awg /usr/local/share/hestia-panel/current
install -d -m0751 /etc/hestia
install -d -m0755 /usr/local/lib/hestia /usr/local/share/hestia-panel/current
cp -r browser/. /usr/local/share/hestia-panel/current/
chmod -R a+rX /usr/local/share/hestia-panel
install hestia hestia-panel /usr/local/bin/
install tools/src/wg /usr/local/bin/awg
install amneziawg-go /usr/local/lib/hestia/
install -m644 profile.py smoke.py /usr/local/lib/hestia/
install /usr/local/bin/sing-box /usr/local/lib/hestia/sing-box
install -m600 guest-profile.json /etc/hestia/profile.json
install -m600 config/sing-box.json /etc/hestia/
install -m640 -g hestia-snapshot config/snapshot.json /etc/hestia/
sha256sum /etc/hestia/profile.json | cut -d' ' -f1 >/etc/hestia/profile-source.sha256
sha256sum /etc/hestia/sing-box.json | cut -d' ' -f1 >/etc/hestia/profile-backend.sha256
echo 1 >/etc/hestia/.installer-managed
chmod 600 /etc/hestia/.installer-managed /etc/hestia/*.sha256
printf '%s\n' 'amneziawg-go=3.1.20260828 commit=b5928efb6ca19f0153958460c3d141f04abc5c2e' 'amneziawg-tools=3.1.20260812 commit=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843' >/etc/hestia/.awg-runtime-version
chmod 600 /etc/hestia/.awg-runtime-version
python3 -I profile.py --validate-managed /etc/hestia
sed 's/@PANEL_LISTEN@/192.168.1.133:8080/g' hestia-panel.service.in >hestia-panel.service
install -m440 hestia-awg.sudoers /etc/sudoers.d/hestia-awg
install -m644 ./*.service ./*.path /etc/systemd/system/
install -m644 ./*.conf /etc/tmpfiles.d/
systemd-tmpfiles --create /etc/tmpfiles.d/hestia-binding.conf /etc/tmpfiles.d/hestia-awg.conf
install_backend_credential ./stage1-backend-credential.dropin
systemctl daemon-reload
flock -u 9
systemctl enable --now hestia-binding-watch.path
systemctl restart hestia-sing-box hestia hestia-panel
for unit in hestia-sing-box hestia hestia-panel; do systemctl is-active --quiet "$unit"; done
systemctl start hestia-smoke@current.service
for endpoint in api/awg api/groups-and-rules api/dns/policy; do
    curl --noproxy '*' --retry 4 --retry-connrefused -fsS "http://192.168.1.133:8080/$endpoint" >/dev/null
done
curl --noproxy '*' --retry 4 --retry-connrefused --fail -s http://192.168.1.133:8080/ | grep -o '<title>[^<]*'
