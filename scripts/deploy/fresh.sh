#!/usr/bin/env bash
# Install a prebuilt full Linux bundle only when no Hestia configuration exists.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && $(hostname -s) == "$2" && $(uname -m) == aarch64 ]] || exit 2
[[ $(readlink /proc/self/fd/8) == /run/hestia-deploy.lock ]] || exit 2
flock -n 8
bundle=$(realpath "$1")
[[ -d $bundle/repo/deploy && -f $bundle/manifest.json && ! -L $bundle ]]
[[ ! -e /etc/hestia && ! -L /etc/hestia ]] || exit 2
[[ $(stat -c %u "$bundle") == 0 && $(stat -c %a "$bundle") == 700 ]] || exit 1
[[ -z $(find "$bundle" \( ! -type d ! -type f -o ! -user root -o -perm /0022 \) -print -quit) ]] || exit 1
[[ -z $(find "$bundle/browser" -mindepth 1 ! -type d ! -type f -print -quit) ]] || exit 1
python3 -B -I - "$bundle" <<'PYVERIFY'
import sys
sys.path.insert(0, sys.argv[1] + '/scripts')
from common import verify_bundle
assert verify_bundle(sys.argv[1])['platform'] == 'linux-arm64'
PYVERIFY
# shellcheck source=../shared/paths.sh
source "$bundle/scripts/paths.sh"
marker=/etc/hestia/.initial-install
for parent in /etc /etc/systemd/system /etc/sudoers.d /usr/local/bin /usr/local/lib /usr/local/share /var/backups; do
    [[ -d $parent && ! -L $parent && $(stat -c %u "$parent") == 0 ]] || exit 1
    mode=$(stat -c %a "$parent")
    (((8#$mode & 0022) == 0)) || exit 1
done
units=(hestia-panel.service hestia.service hestia-sing-box.service hestia-dns.service hestia-binding-watch.path hestia-binding-watch.service hestia-binding-recovery.service hestia-geoip-publish.timer hestia-geoip-publish.service)
paths=(/etc/hestia /usr/local/lib/hestia /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/hestia-observe /usr/local/bin/hestia-export-config /usr/local/bin/awg /usr/local/share/hestia-panel /usr/share/hestia /etc/sudoers.d/hestia-panel /etc/systemd/system/hestia.service.d /etc/systemd/system/hestia-awg@.service /etc/systemd/system/hestia-smoke@.service /etc/tmpfiles.d/hestia-awg.conf /etc/tmpfiles.d/hestia-binding.conf /etc/sysctl.d/80-hestia-geoip.conf /var/lib/hestia-country-map /var/lib/hestia-dns-policy /var/lib/hestia-traffic /var/lib/hestia-quality-settings /var/lib/hestia-geoip-overrides /var/lib/hestia-geoip-proposals /var/lib/private/hestia-dns /var/lib/hestia-dns /run/hestia-install.lock /run/hestia-awg /run/amneziawg)
for unit in "${units[@]}"; do paths+=("/etc/systemd/system/$unit"); done
# Refuse partial installations before any account, service or application mutation.
[[ -z $(systemctl list-units 'hestia-awg*' --state=active --no-legend) ]] || exit 1
[[ ! -d /etc/hestia/awg || -z $(find /etc/hestia/awg -mindepth 1 -maxdepth 1 -print -quit) ]] || exit 1
[[ ! -e /usr/local/share/hestia-panel/new && ! -L /usr/local/share/hestia-panel/new ]] || exit 1
for path in "${paths[@]}"; do
    if [[ -e $path || -L $path ]]; then
        [[ ! -L $path && $(stat -c %u "$path") == 0 ]] || {
            # The panel's own state directories may belong to its dedicated service account.
            [[ -d $path && ! -L $path && $path == /var/lib/hestia-* && $(stat -c %U "$path") == hestia-panel ]] || exit 1
        }
        mode=$(stat -c %a "$path")
        (((8#$mode & 0022) == 0)) || exit 1
    fi
done
for path in /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/hestia-observe /usr/local/lib/hestia /usr/local/share/hestia-panel /etc/systemd/system/hestia.service /etc/systemd/system/hestia-panel.service; do
    [[ ! -e $path && ! -L $path ]] || exit 1
done
backup=$(mktemp -d /var/backups/hestia-initial-install.XXXXXXXX)
declare -A active enabled
for unit in "${units[@]}"; do
    active[$unit]=$(systemctl is-active "$unit" 2>/dev/null || :)
    enabled[$unit]=$(systemctl is-enabled "$unit" 2>/dev/null || :)
done
backup_ready=0
base_complete=0
released=0
new_panel=0
new_snapshot=0
getent passwd hestia-panel >/dev/null || new_panel=1
getent group hestia-snapshot >/dev/null || new_snapshot=1
# fresh_identity fingerprints the newly published configuration and application before activation.
fresh_identity() {
    python3 -I - <<'PYIDENTITY'
from pathlib import Path
import hashlib
h = hashlib.sha256()
for name in ('/etc/hestia', '/usr/local/lib/hestia', '/usr/local/share/hestia-panel', '/usr/local/bin/hestia', '/usr/local/bin/hestia-panel', '/usr/local/bin/hestia-observe', '/usr/local/bin/awg'):
    root = Path(name)
    for path in [root] + (sorted(root.rglob('*')) if root.is_dir() else []):
        if path.is_symlink(): raise SystemExit('Unexpected fresh-generation symlink')
        h.update(str(path).encode() + b'\0')
        if path.is_file(): h.update(hashlib.sha256(path.read_bytes()).digest())
        elif not path.is_dir(): raise SystemExit('Unexpected fresh-generation file type')
print(h.hexdigest())
PYIDENTITY
}
# rollback restores only the enumerated application paths and prior service states on failure.
rollback() {
    local rc=$? path unit
    trap - EXIT
    if ((rc)); then
        set +e
        if ((backup_ready)); then
            if [[ -e /etc/hestia && $base_complete == 0 ]]; then
                echo "Base installation did not return an owned generation; preserving state and backup $backup" >&2
                exit 1
            fi
            if [[ -f /run/hestia-install.lock && ! -L /run/hestia-install.lock ]]; then
                if [[ $(readlink /proc/self/fd/9) != /run/hestia-install.lock ]]; then exec 9<>/run/hestia-install.lock; fi
                flock -w 30 9 || {
                    echo "Fresh rollback lock unavailable; backup $backup" >&2
                    exit 1
                }
            fi
            [[ ! -e /etc/hestia/.binding-pending && ! -L /etc/hestia/.binding-pending ]] || {
                echo "Pending binding; fresh rollback refused" >&2
                exit 1
            }
            if ((released)); then
                [[ $(fresh_identity) == "$(cat "$backup/published.sha256")" ]] || {
                    echo "Fresh generation changed; preserving backup $backup" >&2
                    exit 1
                }
            fi
            stop_existing_units "${units[@]}" || {
                echo "Fresh rollback could not stop services; backup $backup" >&2
                exit 1
            }
            systemctl disable "${units[@]}" >/dev/null 2>&1
            for path in "${paths[@]}"; do [[ $path == /run/hestia-install.lock ]] || rm -rf -- "$path" || {
                echo "Fresh rollback removal failed; backup $backup" >&2
                exit 1
            }; done
            tar -C / -xpf "$backup/files.tar" || {
                echo "Fresh rollback restore failed; backup $backup" >&2
                exit 1
            }
            sysctl -w "fs.inotify.max_user_instances=$(cat "$backup/inotify")" >/dev/null
        fi
        if ((new_snapshot)) && [[ -f /run/hestia-install.lock && ! -L /run/hestia-install.lock ]]; then
            chown root:root /run/hestia-install.lock
            chmod 0600 /run/hestia-install.lock
        fi
        ((new_panel == 0)) || userdel hestia-panel
        ((new_snapshot == 0)) || groupdel hestia-snapshot
        flock -u 9 2>/dev/null || :
        systemctl daemon-reload
        for unit in "${units[@]}"; do
            [[ ${enabled[$unit]} != enabled ]] || systemctl enable "$unit"
            [[ ${active[$unit]} != active || $unit == hestia-binding-watch.service ]] || systemctl start "$unit"
        done
        echo "Initial installation failed; application backup: $backup" >&2
    fi
    exit "$rc"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
systemctl stop hestia-panel.service hestia-binding-watch.path hestia-binding-watch.service 2>/dev/null || :
# Drain any detached writer before recording files; panel and watchdog cannot start new writers.
if [[ -f /run/hestia-install.lock ]]; then
    exec 9<>/run/hestia-install.lock
    flock -w 95 9
fi
existing=()
for path in "${paths[@]}"; do [[ ! -e $path && ! -L $path ]] || existing+=("${path#/}"); done
tar -C / -cpf "$backup/files.tar" "${existing[@]}" --files-from /dev/null
ip -4 route show table main >"$backup/routes4"
ip -6 route show table main >"$backup/routes6"
sysctl -n fs.inotify.max_user_instances >"$backup/inotify"
backup_ready=1
if [[ -f /run/hestia-install.lock ]]; then flock -u 9; fi
if ((new_snapshot)); then groupadd --system hestia-snapshot; fi
if ((new_panel)); then useradd --system --user-group --no-create-home --shell /usr/sbin/nologin hestia-panel; fi
config=()
[[ -f $marker ]] || config=(--config "$bundle/scripts/default-profile.json")
bash "$bundle/repo/deploy/install.sh" --controller-binary "$bundle/bin/hestia" --sing-box-archive "$bundle/sing.tgz" "${config[@]}"
exec 9<>/run/hestia-install.lock
flock -n 9
mkdir "$backup/expected"
python3 -I "$bundle/repo/deploy/profile.py" "$bundle/scripts/default-profile.json" "$backup/expected"
python3 -I - "$bundle/scripts/default-profile.json" "$backup/expected" <<'PYEXPECTED'
from pathlib import Path
import hashlib, sys
root = Path('/etc/hestia')
expected = Path(sys.argv[2])
names = {'.installer-managed', 'profile.json', 'snapshot.json', 'sing-box.json', 'profile-source.sha256', 'profile-backend.sha256'}
if {p.name for p in root.iterdir()} != names or any(p.is_symlink() or not p.is_file() for p in root.iterdir()):
    raise SystemExit('Unexpected initial configuration generation; preserving state')
if (root / 'profile.json').read_bytes() != Path(sys.argv[1]).read_bytes(): raise SystemExit('Initial profile changed')
for name in ('snapshot.json', 'sing-box.json'):
    if (root / name).read_bytes() != (expected / name).read_bytes(): raise SystemExit('Initial backend generation changed')
for name, content in (('profile-source.sha256', (root / 'profile.json').read_bytes()), ('profile-backend.sha256', (root / 'sing-box.json').read_bytes())):
    if (root / name).read_text().strip() != hashlib.sha256(content).hexdigest(): raise SystemExit('Initial source marker changed')
if (root / '.installer-managed').read_text().strip() != '1': raise SystemExit('Initial management marker changed')
PYEXPECTED
cmp /usr/local/bin/hestia "$bundle/bin/hestia"
base_complete=1
install -d -m 0755 /usr/local/share/hestia-panel /usr/local/lib/hestia
install -m 0755 "$bundle/bin/hestia-panel" /usr/local/bin/hestia-panel
install -m 0755 "$bundle/bin/hestia-observe" /usr/local/bin/hestia-observe
install -m 0755 "$bundle/bin/amneziawg-go" /usr/local/lib/hestia/amneziawg-go
install -m 0755 "$bundle/bin/awg" /usr/local/bin/awg
install -d -m 0700 /etc/hestia/awg
cp -R "$bundle/browser" /usr/local/share/hestia-panel/new
chown -R root:root /usr/local/share/hestia-panel/new
find /usr/local/share/hestia-panel/new -type d -exec chmod 0755 {} +
find /usr/local/share/hestia-panel/new -type f -exec chmod 0644 {} +
rm -rf /usr/local/share/hestia-panel/current
mv /usr/local/share/hestia-panel/new /usr/local/share/hestia-panel/current
sed 's/@PANEL_LISTEN@/127.0.0.1:8080/g' "$bundle/repo/deploy/systemd/hestia-panel.service.in" >"$backup/panel.service"
install -m 0644 "$backup/panel.service" /etc/systemd/system/hestia-panel.service
cat "$bundle/repo/deploy/systemd/hestia-awg.sudoers" >"$backup/panel.sudoers"
printf '%s\n' 'hestia-panel ALL=(root) NOPASSWD: /usr/local/bin/hestia -apply-binding' >>"$backup/panel.sudoers"
visudo -cf "$backup/panel.sudoers"
install -m 0440 "$backup/panel.sudoers" /etc/sudoers.d/hestia-panel
install -m 0644 "$bundle/repo/deploy/systemd/hestia-awg@.service" /etc/systemd/system/hestia-awg@.service
install -m 0644 "$bundle/repo/deploy/systemd/hestia-awg.conf" /etc/tmpfiles.d/hestia-awg.conf
printf '%s\n' 'amneziawg-go=3.1.20260828 amneziawg-tools=3.1.20260812' >/etc/hestia/.awg-runtime-version
printf '%s\n' 'linux initial local-only' >"$marker"
systemd-tmpfiles --create /etc/tmpfiles.d/hestia-awg.conf /etc/tmpfiles.d/hestia-binding.conf
fresh_identity >"$backup/published.sha256"
released=1
flock -u 9
install -d -o hestia-panel -g root -m 2750 /var/lib/hestia-country-map
systemctl daemon-reload
systemctl enable --now hestia-panel.service
systemctl restart hestia-panel.service
for attempt in {1..30}; do
    curl --silent --fail http://127.0.0.1:8080/api/groups-and-rules -o /dev/null && break
    ((attempt < 30)) || exit 1
    sleep 0.2
done
python3 /usr/local/lib/hestia/smoke.py
ip -4 route show table main | cmp -s "$backup/routes4" -
ip -6 route show table main | cmp -s "$backup/routes6" -
(cd / && sha256sum usr/local/bin/hestia usr/local/bin/hestia-panel usr/local/bin/hestia-observe usr/local/lib/hestia/amneziawg-go usr/local/bin/awg usr/local/lib/hestia/sing-box) >"$backup/installed.sha256"
echo "Initial installation complete; backup=$backup"
cat "$backup/installed.sha256"
