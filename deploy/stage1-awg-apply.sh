#!/usr/bin/env bash
# Apply a prebuilt Hestia/AWG bundle only to the existing managed stage1 guest.
set -euo pipefail
umask 077

# die prints a fatal preflight or update error and exits nonzero.
die() {
	echo "$*" >&2
	exit 1
}

[[ $# == 1 && $EUID == 0 ]] || die "Usage: sudo bash stage1-awg-apply.sh PACKAGE_DIRECTORY"
bundle=$(realpath -e -- "$1")
[[ $bundle == "$1" && -d $bundle && ! -L $1 && $(stat -c '%u:%a' -- "$bundle") == 0:700 ]] || die "Package directory must be canonical, root-owned, and mode 0700"
[[ $(hostname -s) == lima-hestia-stage1 ]] || die "Refusing a guest other than lima-hestia-stage1"
ip -4 -o addr show dev lima0 scope global | awk '$4 ~ /^192\.168\.1\.133\// { found=1 } END { exit !found }' || die "Refusing a guest without 192.168.1.133 on lima0"

# die_if_untrusted_dir checks every existing component without following symlinks; target trees must be root-owned and not writable by group/other.
die_if_untrusted_dir() {
	local path=$1 current=/ part owner mode
	[[ $path == /* ]] || die "Expected an absolute path: $path"
	IFS=/ read -r -a parts <<<"${path#/}"
	for part in "${parts[@]}"; do
		[[ -n $part ]] || continue
		current=${current%/}/$part
		[[ ! -L $current ]] || die "Symlink in trusted path: $current"
		[[ -d $current ]] || die "Required parent directory is missing: $current"
		read -r owner mode < <(stat -c '%u %a' -- "$current")
		((owner == 0 && (8#$mode & 0022) == 0)) || die "Untrusted directory ownership/mode: $current"
	done
}

# die_if_untrusted_file rejects symlinks, non-regular files and writable/unowned existing targets before replacement.
die_if_untrusted_file() {
	local path=$1 owner mode
	[[ ! -L $path ]] || die "Symlink target is not allowed: $path"
	[[ ! -e $path ]] && return 0
	[[ -f $path ]] || die "Target is not a regular file: $path"
	read -r owner mode < <(stat -c '%u %a' -- "$path")
	((owner == 0 && (8#$mode & 0022) == 0)) || die "Untrusted target ownership/mode: $path"
}

# tree_digest returns a stable digest over paths and bytes, rejecting links and special files.
tree_digest() {
	python3 -I - "$1" <<'PY'
import hashlib, os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
if not root.is_dir() or root.is_symlink():
    raise SystemExit(f"asset root is not a real directory: {root}")
h = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise SystemExit(f"unsafe asset entry: {path}")
    if stat.S_ISREG(info.st_mode):
        rel = path.relative_to(root).as_posix().encode()
        h.update(rel + b"\0" + hashlib.sha256(path.read_bytes()).digest())
print(h.hexdigest()[:20])
PY
}

# require_root_file verifies an existing required file before it is inspected or replaced.
require_root_file() {
	local path=$1
	die_if_untrusted_file "$path"
	[[ -f $path ]] || die "Required managed file is missing: $path"
}

# config_digest hashes only non-secret managed topology/configuration files for before/after comparison.
config_digest() {
	sha256sum /etc/hestia/snapshot.json /etc/hestia/sing-box.json \
		/etc/hestia/profile.json /etc/wireguard/wg-keenetic.conf
}

[[ -f /etc/hestia/.installer-managed && ! -L /etc/hestia/.installer-managed &&
	$(stat -c '%u:%a' /etc/hestia/.installer-managed) == 0:600 &&
	$(cat /etc/hestia/.installer-managed) == 1 ]] || die "Refusing an unmanaged Hestia installation"
[[ ! -e /etc/hestia/.binding-pending && ! -L /etc/hestia/.binding-pending ]] || die "Recover the pending binding transaction before updating"

# Establish safe parents and target states before lock acquisition or any system mutation.
for dir in /etc /etc/hestia /etc/systemd /etc/systemd/system /etc/tmpfiles.d /etc/sudoers.d \
	/usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/hestia \
	/usr/local/share /usr/local/share/hestia-panel /usr/local/share/hestia-panel/releases \
	/run /var /var/backups /etc/wireguard; do
	die_if_untrusted_dir "$dir"
done
for dir in /etc/hestia/awg /run/hestia-awg; do
	if [[ -e $dir || -L $dir ]]; then
		die_if_untrusted_dir "$dir"
		if [[ $dir == /etc/hestia/awg && $(stat -c '%u:%a' "$dir") != 0:700 ]]; then
			die "AWG profile store must be root-owned mode 0700"
		fi
	fi
done
for path in /etc/hestia/.installer-managed /etc/hestia/.binding-pending /etc/hestia/profile.json \
	/etc/hestia/snapshot.json /etc/hestia/sing-box.json \
	/run/hestia-install.lock /run/hestia-awg/ready /run/hestia-awg/health.json /run/hestia-awg/routes.json \
	/usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/awg \
	/usr/local/bin/hestia.next /usr/local/bin/hestia-panel.next /usr/local/bin/awg.next \
	/usr/local/lib/hestia/profile.py /usr/local/lib/hestia/amneziawg-go \
	/usr/local/lib/hestia/profile.py.next /usr/local/lib/hestia/amneziawg-go.next \
	/usr/local/share/hestia-panel/current /etc/hestia/.awg-runtime-version \
	/usr/local/share/hestia-panel/current.next \
	/etc/systemd/system/hestia.service /etc/systemd/system/hestia-panel.service \
	/etc/systemd/system/hestia-awg.service /etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg; do
	parent=${path%/*}
	if [[ $parent == /run/hestia-awg && ! -e $parent && ! -L $parent ]]; then
		: # systemd-tmpfiles creates this runtime directory after installation.
	else
		die_if_untrusted_dir "$parent"
	fi
	if [[ $path == */current ]]; then
		[[ ! -e $path || -L $path ]] || die "Panel current must be a symlink: $path"
		if [[ -L $path ]]; then
			link=$(readlink -- "$path")
			[[ $link =~ ^releases/[0-9a-f]{20}$ ]] || die "Unexpected panel release symlink: $link"
			die_if_untrusted_dir "$parent/${link%/*}"
			die_if_untrusted_dir "$parent/$link"
		fi
	else
		die_if_untrusted_file "$path"
	fi
done
for path in /usr/local/bin/hestia.next /usr/local/bin/hestia-panel.next /usr/local/bin/awg.next \
	/usr/local/lib/hestia/profile.py.next /usr/local/lib/hestia/amneziawg-go.next \
	/usr/local/share/hestia-panel/current.next; do
	[[ ! -e $path && ! -L $path ]] || die "Stale staging target exists: $path"
done

[[ -e /run/hestia-install.lock ]] || die "The managed installer lock is missing"
[[ $(stat -c '%u' /run/hestia-install.lock) == 0 ]] || die "The managed installer lock is not root-owned"
exec 9<>/run/hestia-install.lock
flock -n 9 || die "Another Hestia transaction is running"

for service in wg-quick@wg-keenetic.service hestia-sing-box.service hestia.service hestia-panel.service; do
	[[ $(systemctl is-active "$service" 2>/dev/null || :) == active ]] || die "Required service is not active: $service"
done
[[ $(systemctl is-active hestia-awg.service 2>/dev/null || :) != active ]] || die "Refusing to replace an active AWG runtime"
[[ ! -e /run/hestia-awg/ready && ! -e /run/hestia-awg/routes.json && ! -e /run/hestia-awg/health.json ]] || die "Stale AWG runtime state exists; inspect before updating"
require_root_file /etc/hestia/profile.json
require_root_file /etc/hestia/snapshot.json
require_root_file /etc/hestia/sing-box.json
require_root_file /etc/wireguard/wg-keenetic.conf
[[ $(stat -c '%u' /etc/wireguard/wg-keenetic.conf) == 0 ]] || die "wg-keenetic config is not root-owned"
getent group hestia-snapshot >/dev/null || die "hestia-snapshot group is missing"
getent passwd hestia-panel >/dev/null || die "Static hestia-panel account is missing"
[[ $(getent passwd hestia-panel | cut -d: -f7) == /usr/sbin/nologin ]] || die "hestia-panel is not a locked service account"
[[ $(systemctl show hestia-panel.service -p FragmentPath --value) == /etc/systemd/system/hestia-panel.service ]] || die "Expected managed hestia-panel.service was not found"
grep -Fq -- '-listen 192.168.1.133:8080' /etc/systemd/system/hestia-panel.service || die "The current panel listener differs from stage1"
[[ $(systemctl is-enabled hestia-panel.service 2>/dev/null || :) == enabled ]] || die "The panel unit must already be enabled"

(cd "$bundle" && sha256sum --check SHA256SUMS)
"$bundle/amneziawg-go" --version | grep -F "amneziawg-go v3.1.20260828" >/dev/null || die "The bundled AmneziaWG runtime version is unexpected"
python3 -I "$bundle/profile.py" --validate-managed /etc/hestia
python3 -I -c 'import json,sys; p=json.load(open(sys.argv[1])); raise SystemExit(1 if any(c.get("status")=="ready" for c in p.get("connectors", [])) else 0)' /etc/hestia/profile.json || die "Refusing an update while an AWG connector is marked ready"

expected_version=$'amneziawg-go=3.1.20260828 commit=b5928efb6ca19f0153958460c3d141f04abc5c2e\namneziawg-tools=3.1.20260812 commit=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'
printf '%s\n' "$expected_version" >"$bundle/awg-version"
if [[ -e /etc/hestia/.awg-runtime-version ]]; then
	[[ $(cat /etc/hestia/.awg-runtime-version) == "$expected_version" ]] || die "AWG version marker conflicts with the pinned package"
elif [[ -e /usr/local/lib/hestia/amneziawg-go || -e /usr/local/bin/awg || -e /etc/systemd/system/hestia-awg.service || -e /etc/tmpfiles.d/hestia-awg.conf || -e /etc/sudoers.d/hestia-awg ]]; then
	die "AWG files exist without a managed version marker"
fi
for pair in "hestia-awg.service:$bundle/hestia-awg.service:/etc/systemd/system/hestia-awg.service" \
	"hestia-awg.conf:$bundle/hestia-awg.conf:/etc/tmpfiles.d/hestia-awg.conf" \
	"hestia-awg.sudoers:$bundle/hestia-awg.sudoers:/etc/sudoers.d/hestia-awg"; do
	IFS=: read -r _ src dst <<<"$pair"
	if [[ -e $dst ]] && ! cmp -s "$src" "$dst"; then die "Unmanaged AWG configuration conflicts with package: $dst"; fi
done

if ! command -v make >/dev/null || ! command -v gcc >/dev/null; then die "The existing guest needs make and gcc to build the pinned awg tools"; fi
build_dir=$(mktemp -d /tmp/hestia-awg-tools.XXXXXX)
trap 'rm -rf -- "$build_dir"' EXIT
tar -xf "$bundle/amneziawg-tools-source.tar" -C "$build_dir"
make -C "$build_dir/src"
"$build_dir/src/wg" --version | grep -F "v3.1.20260812" >/dev/null || die "The built awg utility version is unexpected"
visudo -cf "$bundle/hestia-awg.sudoers" >/dev/null

asset_id=$(tree_digest "$bundle/browser")
asset_release=/usr/local/share/hestia-panel/releases/$asset_id
if [[ -e $asset_release || -L $asset_release ]]; then
	[[ -d $asset_release && ! -L $asset_release ]] || die "Digest-named panel release is not a real directory"
	read -r release_owner release_mode < <(stat -c '%u %a' -- "$asset_release")
	((release_owner == 0 && (8#$release_mode & 0022) == 0)) || die "Untrusted digest-named panel release directory"
	while IFS= read -r -d '' entry; do
		[[ ! -L $entry ]] || die "Symlink in installed panel release: $entry"
		read -r owner mode < <(stat -c '%u %a' -- "$entry")
		((owner == 0 && (8#$mode & 0022) == 0)) || die "Untrusted installed panel release entry: $entry"
	done < <(find "$asset_release" -mindepth 1 -print0)
	[[ $(tree_digest "$asset_release") == "$asset_id" ]] || die "Existing digest-named panel release content does not match its name"
fi

# Preflight every file that the package will replace, including the rendered panel service.
sed 's|@PANEL_LISTEN@|192.168.1.133:8080|g' "$bundle/hestia-panel.service.in" >"$build_dir/hestia-panel.service"
for path in /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/awg \
	/usr/local/lib/hestia/profile.py /usr/local/lib/hestia/amneziawg-go \
	/etc/hestia/.awg-runtime-version /etc/systemd/system/hestia.service \
	/etc/systemd/system/hestia-panel.service /etc/systemd/system/hestia-awg.service \
	/etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg; do
	die_if_untrusted_file "$path"
done

backup=/var/backups/hestia-stage1-awg-$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -e $backup && ! -L $backup ]] || die "Backup path already exists: $backup"
for path in /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/awg \
	/usr/local/lib/hestia/profile.py /usr/local/lib/hestia/amneziawg-go \
	/etc/hestia/.awg-runtime-version /etc/systemd/system/hestia.service \
	/etc/systemd/system/hestia-panel.service /etc/systemd/system/hestia-awg.service \
	/etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg \
	/usr/local/share/hestia-panel/current; do
	if [[ -e $path || -L $path ]]; then
		if [[ $path == */current ]]; then [[ -L $path ]] || die "Panel current is not a symlink"; else die_if_untrusted_file "$path"; fi
	fi
done

# All targets and parents are now preflighted; the following creates a manual recovery copy before replacing system files.
install -d -o root -g root -m 0700 "$backup"
install -d -o root -g root -m 0700 /etc/hestia/awg
cat >"$backup/README.txt" <<EOF
Manual backup created before the AWG stage1 update.

To restore, copy each prior file/symlink listed in manifest.txt from files/ back to its original absolute path, then reload systemd and restart hestia.service and hestia-panel.service.

Targets absent from manifest.txt did not exist before this update. Remove those newly installed targets during manual rollback. They include the AWG runtime/tool/version marker, AWG systemd/tmpfiles/sudoers files, updated Hestia and panel binaries/units, and the panel current symlink. Also remove the newly installed browser release below only if no current symlink references it:
  $asset_release

Use state.txt and routes-before.txt to compare service and route state. This backup does not restore or modify the router, WireGuard config, main routes, or Hestia profile/backend/snapshot.
EOF
: >"$backup/manifest.txt"
for path in /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/awg \
	/usr/local/lib/hestia/profile.py /usr/local/lib/hestia/amneziawg-go \
	/etc/hestia/.awg-runtime-version /etc/systemd/system/hestia.service \
	/etc/systemd/system/hestia-panel.service /etc/systemd/system/hestia-awg.service \
	/etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg \
	/usr/local/share/hestia-panel/current; do
	if [[ -e $path || -L $path ]]; then
		name=${path#/}
		mkdir -p "$backup/files/$(dirname "$name")"
		cp -a -- "$path" "$backup/files/$name"
		printf '%s\n' "$path" >>"$backup/manifest.txt"
	fi
done
{
	printf 'enabled/active service states\n'
	for service in wg-quick@wg-keenetic.service hestia-sing-box.service hestia.service hestia-panel.service hestia-awg.service; do
		printf '%s enabled=%s active=%s\n' "$service" "$(systemctl is-enabled "$service" 2>/dev/null || :)" "$(systemctl is-active "$service" 2>/dev/null || :)"
	done
	printf '\nIPv4 default routes\n'
	ip -4 route show default
	printf '\nIPv6 default routes\n'
	ip -6 route show default
	printf '\nconfiguration digests\n'
	config_digest
} >"$backup/state.txt"

routes_before=$backup/routes-before.txt
hashes_before=$backup/config-before.sha256
{
	printf 'IPv4 default routes\n'
	ip -4 route show default
	printf 'IPv6 default routes\n'
	ip -6 route show default
} >"$routes_before"
config_digest >"$hashes_before"

install -d -o root -g root -m 0755 /usr/local/share/hestia-panel/releases
if [[ ! -e $asset_release ]]; then
	install -d -o root -g root -m 0755 "$asset_release"
	cp -R "$bundle/browser/." "$asset_release/"
	chown -R root:root "$asset_release"
	chmod -R a-w,go+rX "$asset_release"
fi
ln -s "releases/$asset_id" /usr/local/share/hestia-panel/current.next
mv -fT /usr/local/share/hestia-panel/current.next /usr/local/share/hestia-panel/current
install -o root -g root -m 0755 "$bundle/hestia" /usr/local/bin/hestia.next
mv -fT /usr/local/bin/hestia.next /usr/local/bin/hestia
install -o root -g root -m 0755 "$bundle/hestia-panel" /usr/local/bin/hestia-panel.next
mv -fT /usr/local/bin/hestia-panel.next /usr/local/bin/hestia-panel
install -o root -g root -m 0644 "$bundle/profile.py" /usr/local/lib/hestia/profile.py.next
mv -fT /usr/local/lib/hestia/profile.py.next /usr/local/lib/hestia/profile.py
install -o root -g root -m 0755 "$bundle/amneziawg-go" /usr/local/lib/hestia/amneziawg-go.next
mv -fT /usr/local/lib/hestia/amneziawg-go.next /usr/local/lib/hestia/amneziawg-go
install -o root -g root -m 0755 "$build_dir/src/wg" /usr/local/bin/awg.next
mv -fT /usr/local/bin/awg.next /usr/local/bin/awg
install -o root -g root -m 0600 "$bundle/awg-version" /etc/hestia/.awg-runtime-version
install -o root -g root -m 0644 "$bundle/hestia-awg.service" /etc/systemd/system/hestia-awg.service
install -o root -g root -m 0644 "$bundle/hestia-awg.conf" /etc/tmpfiles.d/hestia-awg.conf
install -o root -g root -m 0440 "$bundle/hestia-awg.sudoers" /etc/sudoers.d/hestia-awg
install -o root -g root -m 0644 "$build_dir/hestia-panel.service" /etc/systemd/system/hestia-panel.service
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
curl --noproxy '*' --fail --silent --show-error --max-time 5 http://192.168.1.133:8080/ -o "$backup/panel-check.html"
grep -q '<html' "$backup/panel-check.html" || die "Panel did not serve its frontend"
{
	printf 'IPv4 default routes\n'
	ip -4 route show default
	printf 'IPv6 default routes\n'
	ip -6 route show default
} >"$backup/routes-after.txt"
config_digest >"$backup/config-after.sha256"
cmp -s "$routes_before" "$backup/routes-after.txt" || die "Main default routes changed; inspect backup $backup"
cmp -s "$hashes_before" "$backup/config-after.sha256" || die "WG-keenetic or profile/backend/snapshot bytes changed unexpectedly; inspect backup $backup"
echo "Stage1 package is installed. Manual backup of replaced files and service state: $backup"
