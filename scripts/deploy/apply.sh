#!/usr/bin/env bash
# Atomically update an existing managed Linux installation, preserving its runtime and configuration.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && $(uname -m) == aarch64 && $(uname -s) == Linux && $(hostname -s) == "$2" ]]
bundle=$(realpath -e "$1")
[[ -d $bundle && ! -L $1 && $(stat -c '%u:%a' "$bundle") == 0:700 ]]
[[ -z $(find "$bundle" \( ! -type d ! -type f -o ! -user root -o -perm /0022 \) -print -quit) ]]
python3 -B -I - "$bundle" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + '/scripts')
from common import verify_bundle
manifest = verify_bundle(sys.argv[1])
if manifest['platform'] != 'linux-arm64' or manifest['experimental']:
    raise SystemExit('Experimental artifacts cannot be deployed')
PY
# shellcheck source=../shared/paths.sh
source "$bundle/scripts/paths.sh"
for directory in /etc /usr/local/bin /usr/local/lib /usr/local/share /var/backups /run; do
    die_if_untrusted_dir "$directory"
done
for file in /run/hestia-deploy.lock /etc/hestia/.installer-managed; do die_if_untrusted_file "$file"; done
exec 8>/run/hestia-deploy.lock
flock -n 8
if [[ ! -e /etc/hestia && ! -L /etc/hestia ]]; then
    exec bash "$bundle/scripts/fresh.sh" "$bundle" "$2"
fi
for directory in /etc/hestia /usr/local/lib/hestia /usr/local/share/hestia-panel; do die_if_untrusted_dir "$directory"; done
[[ -f /etc/hestia/.installer-managed && ! -L /etc/hestia/.installer-managed && $(cat /etc/hestia/.installer-managed) == 1 ]]
for file in /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/hestia-observe /usr/local/lib/hestia/profile.py /usr/local/lib/hestia/smoke.py; do
    die_if_untrusted_file "$file"
    die_if_untrusted_file "$file.next"
    [[ -f $file ]]
done
[[ -d /usr/local/share/hestia-panel/current ]]
if [[ -L /usr/local/share/hestia-panel/current ]]; then
    [[ $(realpath /usr/local/share/hestia-panel/current) == /usr/local/share/hestia-panel/releases/* ]]
fi
[[ $(systemctl is-active hestia-awg.service || :) != active ]]
# shellcheck source=../../deploy/awg-upgrade.sh
source "$bundle/helpers/awg-upgrade.sh"
[[ -f /usr/local/lib/hestia/sing-box && -f /usr/local/lib/hestia/amneziawg-go && -f /usr/local/bin/awg ]]
/usr/local/lib/hestia/sing-box version | head -1 | grep -Fx 'sing-box version 1.14.4'
python3 -I "$bundle/helpers/profile.py" --validate-managed /etc/hestia
"$bundle/bin/hestia" -check -config /etc/hestia/snapshot.json
backup=$(mktemp -d /var/backups/hestia-deploy.XXXXXXXX)
units=(hestia-panel.service hestia-binding-watch.path hestia-binding-watch.service hestia.service hestia-sing-box.service hestia-dns.service)
declare -A active
for unit in "${units[@]}"; do active[$unit]=$(systemctl is-active "$unit" || :); done
mapfile -t awg_units < <(systemctl list-units 'hestia-awg@*.service' --state=active --no-legend | awk '{print $1}')
for unit in "${awg_units[@]}"; do [[ $unit =~ ^hestia-awg@[a-zA-Z0-9-]+\.service$ ]]; done
paths=(usr/local/bin/hestia usr/local/bin/hestia-panel usr/local/bin/hestia-observe usr/local/lib/hestia/profile.py usr/local/lib/hestia/smoke.py usr/local/share/hestia-panel/current)
ready=0
published=0
released=0
# config_digest fingerprints all retained configuration files without logging their contents.
config_digest() {
    python3 -I - <<'PY'
from pathlib import Path
import hashlib
root = Path('/etc/hestia')
digest = hashlib.sha256()
for path in sorted(root.rglob('*')):
    if path.is_symlink(): raise SystemExit('Configuration link is unsupported')
    if not (path.is_file() or path.is_dir()): raise SystemExit('Configuration special file is unsupported')
    if path.is_file():
        digest.update(str(path.relative_to(root)).encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
print(digest.hexdigest())
PY
}
# application_digest detects a newer publication before rollback can replace managed paths.
application_digest() {
    python3 -I - "${paths[@]}" <<'PYAPP'
from pathlib import Path
import hashlib, os, sys
h = hashlib.sha256()
for name in sys.argv[1:]:
    root = Path('/') / name
    entries = [root] + (sorted(root.rglob('*')) if root.is_dir() and not root.is_symlink() else [])
    for path in entries:
        h.update(str(path).encode() + b'\0')
        if path.is_symlink(): h.update(os.readlink(path).encode())
        elif path.is_file(): h.update(hashlib.sha256(path.read_bytes()).digest())
        elif not path.is_dir(): raise SystemExit('Managed application path disappeared')
print(h.hexdigest())
PYAPP
}
# resume starts only services that were active before this update, releasing the binding lock first.
resume() {
    flock -u 9 || :
    for unit in "${awg_units[@]}"; do systemctl start "$unit" || return 1; done
    for unit in hestia-sing-box.service hestia.service hestia-dns.service hestia-panel.service hestia-binding-watch.path; do
        [[ ${active[$unit]} != active ]] || systemctl start "$unit" || return 1
    done
}
# rollback restores previous application files only when configuration has not changed concurrently.
rollback() {
    local rc=$?
    trap - EXIT
    if ((rc)); then
        set +e
        if ((ready)); then
            flock -x -w 30 9 || {
                echo "Rollback lock unavailable; backup $backup" >&2
                exit 1
            }
            [[ ! -e /etc/hestia/.binding-pending && ! -L /etc/hestia/.binding-pending ]] || {
                echo "Pending transaction; rollback refused, backup $backup" >&2
                exit 1
            }
            if [[ $(config_digest) != "$(cat "$backup/config.sha256")" ]]; then
                echo "Configuration changed; no destructive rollback. Backup $backup" >&2
                exit 1
            fi
            if ((released)) && [[ $(application_digest) != "$(cat "$backup/published.sha256")" ]]; then
                echo "Newer application publication detected; preserving backup $backup" >&2
                exit 1
            fi
            stop_existing_units "${units[@]}" "${awg_units[@]}" || {
                echo "Rollback could not stop services; backup $backup" >&2
                exit 1
            }
            if ((published)); then
                rm -rf /usr/local/share/hestia-panel/current
                tar -C / -xpf "$backup/files.tar" || {
                    echo "Rollback restoration failed; backup $backup" >&2
                    exit 1
                }
            fi
        fi
        resume || {
            echo "Rollback service restoration failed; backup $backup" >&2
            exit 1
        }
        echo "Update failed; prior application restored, backup $backup" >&2
    fi
    exit "$rc"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
systemctl stop hestia-panel.service hestia-binding-watch.path hestia-binding-watch.service
[[ -f /run/hestia-install.lock && ! -L /run/hestia-install.lock && $(stat -c %u /run/hestia-install.lock) == 0 ]]
[[ $(stat -c %a /run/hestia-install.lock) == 600 || $(stat -c %a /run/hestia-install.lock) == 640 ]]
exec 9<>/run/hestia-install.lock
flock -x -w 30 9
[[ ! -e /etc/hestia/.binding-pending && ! -L /etc/hestia/.binding-pending ]]
config_digest >"$backup/config.sha256"
tar -C / -cpf "$backup/files.tar" "${paths[@]}"
ip -4 route show table main >"$backup/routes4"
ip -6 route show table main >"$backup/routes6"
ready=1
stop_existing_units hestia.service hestia-sing-box.service hestia-dns.service "${awg_units[@]}"
# Publication occurs while all application writers and runtimes are stopped under the install lock.
published=1
for name in hestia hestia-panel hestia-observe; do
    install -o root -g root -m 0755 "$bundle/bin/$name" "/usr/local/bin/$name.next"
    mv -fT "/usr/local/bin/$name.next" "/usr/local/bin/$name"
done
for name in profile.py smoke.py; do
    install -o root -g root -m 0644 "$bundle/helpers/$name" "/usr/local/lib/hestia/$name.next"
    mv -fT "/usr/local/lib/hestia/$name.next" "/usr/local/lib/hestia/$name"
done
rm -rf /usr/local/share/hestia-panel/current
cp -R "$bundle/browser" /usr/local/share/hestia-panel/current
chown -R root:root /usr/local/share/hestia-panel/current
find /usr/local/share/hestia-panel/current -type d -exec chmod 0755 {} +
find /usr/local/share/hestia-panel/current -type f -exec chmod 0644 {} +
application_digest >"$backup/published.sha256"
released=1
resume
[[ $(config_digest) == "$(cat "$backup/config.sha256")" ]]
python3 -I /usr/local/lib/hestia/profile.py --validate-managed /etc/hestia
plan=$(python3 -I /usr/local/lib/hestia/profile.py --awg-start-plan /etc/hestia)
for unit in "${awg_units[@]}"; do
    id=${unit#hestia-awg@}
    id=${id%.service}
    while read -r planned slot mode count; do
        [[ $planned != "$id" ]] || wait_awg_proof /usr/local/bin/hestia "$id" "$slot" ready "$((30 + 12 * count))"
    done <<<"$plan"
done
systemctl start hestia-smoke@current.service
for unit in "${units[@]}"; do
    [[ ${active[$unit]} != active || $unit == hestia-binding-watch.service ]] || systemctl is-active --quiet "$unit"
done
ip -4 route show table main >"$backup/routes4.after"
ip -6 route show table main >"$backup/routes6.after"
cmp "$backup/routes4" "$backup/routes4.after"
cmp "$backup/routes6" "$backup/routes6.after"
printf 'Update verified; preserved configuration and main routes. Backup: %s\n' "$backup"
