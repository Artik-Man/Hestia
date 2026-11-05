#!/usr/bin/env bash
# Install the immutable bundled database and the validated rule publisher on Debian.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=/usr/share/hestia
overrides=/var/lib/hestia-geoip-overrides
umask 022

# trusted checks an existing root-owned path before installation may reuse it.
trusted() {
    local mode
    [[ ! -L $1 && $(stat -c %u "$1") == 0 ]] || return 1
    mode=$(stat -c %a "$1")
    (((8#$mode & 0022) == 0))
}

for path in /usr/share /var/lib /usr/local/lib /etc/systemd/system /etc/sysctl.d; do trusted "$path"; done
for path in "$root" /usr/local/lib/hestia; do
    if [[ -e $path || -L $path ]]; then trusted "$path" && [[ -d $path ]] || exit 1; else install -d -m 0755 "$path"; fi
done
# Lock the root-owned directory itself, which avoids following or creating a lock file.
exec 8<"$root"
flock 8
# check_country_directory rejects irregular, incomplete, or writable files before a privileged reader opens them.
check_country_directory() {
    python3 -I - "$1" "$2" "$here/../backend/internal/geoip/countries.txt" <<'PYTHON'
import json
import os
from pathlib import Path
import stat
import sys

directory = Path(sys.argv[1])
codes = set(Path(sys.argv[3]).read_text(encoding="ascii").split())
metadata = {"manifest.json", "countries.txt", "country.bin", "NOTICE"} if sys.argv[2] == "base" else set()
found = set()
for entry in os.scandir(directory):
    info = entry.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022:
        sys.exit("unsafe GeoIP file: " + entry.name)
    if entry.name not in metadata and (not entry.name.endswith(".json") or entry.name[:-5] not in codes):
        sys.exit("unexpected GeoIP file: " + entry.name)
    found.add(entry.name)
if sys.argv[2] == "base":
    if not metadata.issubset(found):
        sys.exit("incomplete GeoIP release")
    manifest = directory / "manifest.json"
    if manifest.stat().st_size > 8192:
        sys.exit("invalid GeoIP release manifest")
    available = json.loads(manifest.read_bytes())["countries"]
    if not available or not isinstance(available, list) or not set(available).issubset(codes):
        sys.exit("invalid GeoIP release countries")
    if set((directory / "countries.txt").read_text(encoding="ascii").split()) != codes:
        sys.exit("invalid GeoIP release catalogue")
else:
    available = codes
if found != metadata | {code + ".json" for code in available}:
    sys.exit("incomplete GeoIP country files")
PYTHON
}
archive="$here/geoip/dbip-country-lite-2026-11.csv.gz"
echo "e5c8459d638a272ece7f4d7cfa49dce18d91b4f403f6940ba9249bf0db3781fd  $archive" | sha256sum -c -
if [[ -e $root/geoip || -L $root/geoip ]]; then
    trusted "$root/geoip"
    check_country_directory "$root/geoip" base
else
    work=$(mktemp -d "$root/.geoip.XXXXXXXX")
    trap 'rm -rf -- "$work"' EXIT
    python3 -I "$here/import_geoip.py" "$archive" "$work/geoip"
    install -m 0644 "$here/geoip/README.md" "$work/geoip/NOTICE"
    install -m 0644 "$here/../backend/internal/geoip/countries.txt" "$work/geoip/"
    mv -T "$work/geoip" "$root/geoip"
    rmdir "$work"
    trap - EXIT
fi
if [[ -e $overrides || -L $overrides ]]; then
    trusted "$overrides"
    check_country_directory "$overrides" overrides
else
    initial=$(mktemp -d /var/lib/.hestia-geoip-overrides.XXXXXXXX)
    trap 'rm -rf -- "$initial"' EXIT
    while read -r code; do
        [[ $code =~ ^[A-Z]{2}$ ]]
        printf '%s\n' '{"version":3,"rules":[]}' >"$initial/$code.json"
    done < <(tr -s '[:space:]' '\n' <"$root/geoip/countries.txt")
    chmod 0644 "$initial/"*.json
    chmod 0750 "$initial"
    if getent group hestia-snapshot >/dev/null; then chgrp hestia-snapshot "$initial"; fi
    mv -T "$initial" "$overrides"
    trap - EXIT
fi
# A later-created dynamic service can read the same files after its group is provisioned.
if getent group hestia-snapshot >/dev/null; then chgrp hestia-snapshot "$overrides"; fi

# replace_geoip_file publishes a regular managed file by same-directory rename.
replace_geoip_file() {
    local src=$1 dst=$2 next
    if [[ -e $dst || -L $dst ]]; then trusted "$dst" && [[ -f $dst ]] || return 1; fi
    next=$(mktemp "${dst}.XXXXXXXX")
    install -m 0644 "$src" "$next"
    mv -T "$next" "$dst"
}
replace_geoip_file "$here/publish_geoip.py" /usr/local/lib/hestia/publish_geoip.py
for unit in hestia-geoip-publish.service hestia-geoip-publish.timer; do
    replace_geoip_file "$here/systemd/$unit" "/etc/systemd/system/$unit"
done
# Local sing-box rule sets each use an inotify instance. Preserve a higher system limit.
if (($(sysctl -n fs.inotify.max_user_instances) < 1024)); then
    replace_geoip_file "$here/geoip/80-hestia-geoip.conf" /etc/sysctl.d/80-hestia-geoip.conf
    sysctl -p /etc/sysctl.d/80-hestia-geoip.conf
fi
if id hestia-panel >/dev/null 2>&1; then
    systemd-tmpfiles --create --prefix=/var/lib/hestia-geoip-proposals "$here/geoip/proposals.conf"
fi
systemctl daemon-reload
systemctl enable --now hestia-geoip-publish.timer
