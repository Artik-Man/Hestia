#!/usr/bin/env bash
# Provision only the existing hestia-dev guest with a local-only full application bundle.
set -euo pipefail
umask 077
[[ $# == 1 && $EUID == 0 && $(hostname -s) == lima-hestia-dev && $(uname -m) == aarch64 ]] || exit 2
bundle=$(realpath "$1")
[[ -d $bundle/repo/deploy && -f $bundle/SHA256SUMS && ! -L $bundle ]] || exit 2
[[ $(stat -c %u "$bundle") == 0 && $(stat -c %a "$bundle") == 700 ]] || exit 1
[[ -z $(find "$bundle" \( ! -type d ! -type f -o ! -user root -o -perm /0022 \) -print -quit) ]] || exit 1
[[ -z $(find "$bundle/browser" -mindepth 1 ! -type d ! -type f -print -quit) ]] || exit 1
(cd "$bundle" && sha256sum -c SHA256SUMS)
marker=/etc/hestia/.dev-validation
[[ ! -e /etc/hestia || (-f $marker && ! -L $marker && $(stat -c %u "$marker") == 0) ]] || {
    echo 'Refusing an installation not owned by this dev fixture' >&2
    exit 1
}
if [[ -f $marker ]]; then
    [[ $(stat -c %a "$marker") == 600 && $(cat "$marker") == '66bb2fa dev-local-only' ]] || exit 1
    [[ $(getent passwd hestia-panel | cut -d: -f7) == /usr/sbin/nologin ]] || exit 1
    [[ $(passwd -S hestia-panel | awk '{print $2}') == L ]] || exit 1
fi
for parent in /etc /etc/systemd/system /etc/sudoers.d /usr/local/bin /usr/local/lib /usr/local/share /var/backups; do
    [[ -d $parent && ! -L $parent && $(stat -c %u "$parent") == 0 ]] || exit 1
    mode=$(stat -c %a "$parent")
    (((8#$mode & 0022) == 0)) || exit 1
done
units=(hestia-panel.service hestia.service hestia-sing-box.service hestia-dns.service hestia-binding-watch.path hestia-binding-watch.service hestia-binding-recovery.service hestia-geoip-publish.timer hestia-geoip-publish.service)
paths=(/etc/hestia /usr/local/lib/hestia /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/hestia-observe /usr/local/bin/hestia-export-config /usr/local/bin/awg /usr/local/share/hestia-panel /usr/share/hestia /etc/sudoers.d/hestia-panel /etc/systemd/system/hestia.service.d /etc/systemd/system/hestia-awg@.service /etc/systemd/system/hestia-smoke@.service /etc/tmpfiles.d/hestia-awg.conf /etc/tmpfiles.d/hestia-binding.conf /etc/sysctl.d/80-hestia-geoip.conf /var/lib/hestia-country-map /var/lib/hestia-dns-policy /var/lib/hestia-traffic /var/lib/hestia-quality-settings /var/lib/hestia-geoip-overrides /var/lib/hestia-geoip-proposals /var/lib/private/hestia-dns /var/lib/hestia-dns /run/hestia-install.lock /run/hestia-awg /run/amneziawg)
for unit in "${units[@]}"; do paths+=("/etc/systemd/system/$unit"); done
# This fixture supports safe empty-VPN repeats; active connector upgrades use the product updater.
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
backup=$(mktemp -d /var/backups/hestia-dev-update.XXXXXXXX)
declare -A active enabled
for unit in "${units[@]}"; do
    active[$unit]=$(systemctl is-active "$unit" 2>/dev/null || :)
    enabled[$unit]=$(systemctl is-enabled "$unit" 2>/dev/null || :)
done
backup_ready=0
new_panel=0
new_snapshot=0
getent passwd hestia-panel >/dev/null || new_panel=1
getent group hestia-snapshot >/dev/null || new_snapshot=1
# rollback restores only the enumerated application paths and prior service states on failure.
rollback() {
    local rc=$? path unit
    trap - EXIT
    if ((rc)); then
        set +e
        if ((backup_ready)); then
            systemctl stop "${units[@]}"
            systemctl disable "${units[@]}" >/dev/null 2>&1
            for path in "${paths[@]}"; do rm -rf -- "$path"; done
            tar -C / -xpf "$backup/files.tar"
            sysctl -w "fs.inotify.max_user_instances=$(cat "$backup/inotify")" >/dev/null
        fi
        flock -u 9 2>/dev/null || :
        systemctl daemon-reload
        for unit in "${units[@]}"; do
            [[ ${enabled[$unit]} != enabled ]] || systemctl enable "$unit"
            [[ ${active[$unit]} != active || $unit == hestia-binding-watch.service ]] || systemctl start "$unit"
        done
        ((new_panel == 0)) || userdel hestia-panel
        ((new_snapshot == 0)) || groupdel hestia-snapshot
        echo "Dev installation failed; application backup: $backup" >&2
    fi
    exit "$rc"
}
trap rollback EXIT
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
[[ -f $marker ]] || config=(--config "$bundle/repo/tests/lab/dev-validation/profile.json")
bash "$bundle/repo/deploy/install.sh" --controller-binary "$bundle/hestia" --sing-box-archive "$bundle/sing.tgz" "${config[@]}"
exec 9<>/run/hestia-install.lock
flock -n 9
install -d -m 0755 /usr/local/share/hestia-panel /usr/local/lib/hestia
install -m 0755 "$bundle/hestia-panel" /usr/local/bin/hestia-panel
install -m 0755 "$bundle/hestia-observe" /usr/local/bin/hestia-observe
install -m 0755 "$bundle/amneziawg-go" /usr/local/lib/hestia/amneziawg-go
install -m 0755 "$bundle/awg" /usr/local/bin/awg
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
printf '%s\n' '66bb2fa dev-local-only' >"$marker"
systemd-tmpfiles --create /etc/tmpfiles.d/hestia-awg.conf /etc/tmpfiles.d/hestia-binding.conf
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
echo "Dev installation complete; backup=$backup"
cat "$backup/installed.sha256"
