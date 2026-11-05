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

# shellcheck source=awg-upgrade.sh
source "$bundle/awg-upgrade.sh"
adopt_profile=0
if [[ -e /etc/hestia/.installer-managed || -L /etc/hestia/.installer-managed ]]; then
    [[ -f /etc/hestia/.installer-managed && ! -L /etc/hestia/.installer-managed &&
        $(stat -c '%u:%a' /etc/hestia/.installer-managed) == 0:600 &&
        $(cat /etc/hestia/.installer-managed) == 1 ]] || die "Installer marker conflicts with the managed installation"
else
    [[ ! -e /etc/hestia/profile.json && ! -L /etc/hestia/profile.json &&
        ! -e /etc/hestia/profile-source.sha256 && ! -L /etc/hestia/profile-source.sha256 &&
        ! -e /etc/hestia/profile-backend.sha256 && ! -L /etc/hestia/profile-backend.sha256 ]] || die "Unmanaged profile artifacts exist without an installer marker"
    [[ $(systemctl show hestia.service -p ExecStart --value) == *"/usr/local/bin/hestia -watch -config /etc/hestia/snapshot.json -interval 1s"* &&
    $(systemctl show hestia-panel.service -p ExecStart --value) == *"/usr/local/lib/hestia-ui/hestia-panel -listen 192.168.1.133:8080"* &&
    $(systemctl show hestia-panel.service -p User --value) == "" ]] || die "Unmanaged installation differs from the known stage1 legacy layout"
    adopt_profile=1
fi
[[ ! -e /etc/hestia/.binding-pending && ! -L /etc/hestia/.binding-pending ]] || die "Recover the pending binding transaction before updating"

# Establish safe parents and target states before lock acquisition or any system mutation.
for dir in /etc /etc/hestia /etc/systemd /etc/systemd/system /etc/tmpfiles.d /etc/sudoers.d \
    /usr /usr/local /usr/local/bin /usr/local/lib \
    /usr/local/share /usr/local/share/hestia-panel \
    /run /var /var/backups /etc/wireguard; do
    die_if_untrusted_dir "$dir"
done
if [[ -e /usr/local/share/hestia-panel/releases || -L /usr/local/share/hestia-panel/releases ]]; then
    die_if_untrusted_dir /usr/local/share/hestia-panel/releases
fi
if [[ -e /usr/local/lib/hestia || -L /usr/local/lib/hestia ]]; then
    die_if_untrusted_dir /usr/local/lib/hestia
fi
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
    /usr/local/lib/hestia/profile.py /usr/local/lib/hestia/smoke.py /usr/local/lib/hestia/amneziawg-go \
    /usr/local/lib/hestia/profile.py.next /usr/local/lib/hestia/smoke.py.next /usr/local/lib/hestia/amneziawg-go.next \
    /usr/local/share/hestia-panel/current /etc/hestia/.awg-runtime-version \
    /usr/local/share/hestia-panel/current.next \
    /etc/systemd/system/hestia.service /etc/systemd/system/hestia-panel.service \
    /etc/systemd/system/hestia-awg@.service /etc/systemd/system/hestia-sing-box.service /etc/systemd/system/hestia-smoke@.service /etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg; do
    parent=${path%/*}
    if [[ $parent == /run/hestia-awg && ! -e $parent && ! -L $parent ]]; then
        : # systemd-tmpfiles creates this runtime directory after installation.
    else
        if [[ $parent == /usr/local/lib/hestia && ! -e $parent && ! -L $parent ]]; then
            : # Created after the manual backup, before installing the new runtime.
        else
            die_if_untrusted_dir "$parent"
        fi
    fi
    if [[ $path == */current ]]; then
        if [[ -L $path ]]; then
            link=$(readlink -- "$path")
            [[ $link =~ ^releases/[0-9a-f]{20}$ ]] || die "Unexpected panel release symlink: $link"
            die_if_untrusted_dir "$parent/${link%/*}"
            die_if_untrusted_dir "$parent/$link"
        elif [[ -e $path ]]; then
            die_if_untrusted_dir "$path"
            [[ -f $path/index.html ]] || die "Panel directory lacks index.html"
            [[ -z $(find "$path" \( ! -user root -o -perm /022 -o \( ! -type d ! -type f \) \) -print -quit) ]] || die "Untrusted panel asset tree"
        fi
    else
        die_if_untrusted_file "$path"
    fi
done
for path in /usr/local/bin/hestia.next /usr/local/bin/hestia-panel.next /usr/local/bin/awg.next \
    /usr/local/lib/hestia/profile.py.next /usr/local/lib/hestia/smoke.py.next /usr/local/lib/hestia/amneziawg-go.next \
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
inspect_legacy_awg || die "Untrusted legacy AWG service"
if ((legacy_awg_active == 0)) && [[ -e /run/hestia-awg/health.json ]]; then
    [[ -f /run/hestia-awg/health.json && ! -L /run/hestia-awg/health.json && ! -s /run/hestia-awg/health.json &&
        $(stat -c '%u:%G:%a' /run/hestia-awg/health.json) == 0:hestia-snapshot:640 ]] || die "Untrusted or stale AWG health record"
fi
require_root_file /etc/hestia/profile.json
require_root_file /etc/hestia/snapshot.json
require_root_file /etc/hestia/sing-box.json
require_root_file /etc/wireguard/wg-keenetic.conf
[[ $(stat -c '%u' /etc/wireguard/wg-keenetic.conf) == 0 ]] || die "wg-keenetic config is not root-owned"
if getent passwd hestia-panel >/dev/null; then
    [[ $(getent passwd hestia-panel | cut -d: -f7) == /usr/sbin/nologin ]] || die "hestia-panel is not a locked service account"
fi
[[ $(systemctl show hestia-panel.service -p FragmentPath --value) == /etc/systemd/system/hestia-panel.service ]] || die "Expected managed hestia-panel.service was not found"
grep -Fq -- '-listen 192.168.1.133:8080' /etc/systemd/system/hestia-panel.service || die "The current panel listener differs from stage1"
[[ $(systemctl is-enabled hestia-panel.service 2>/dev/null || :) == enabled ]] || die "The panel unit must already be enabled"

(cd "$bundle" && sha256sum --check SHA256SUMS)
"$bundle/amneziawg-go" --version | grep -F "amneziawg-go v3.1.20260828" >/dev/null || die "The bundled AmneziaWG runtime version is unexpected"
if ((adopt_profile)); then
    python3 -I "$bundle/adopt-profile.py" check /etc/hestia "$bundle/guest-profile.json" "$bundle/profile.py"
else
    python3 -I "$bundle/profile.py" --validate-managed /etc/hestia
fi

expected_version=$'amneziawg-go=3.1.20260828 commit=b5928efb6ca19f0153958460c3d141f04abc5c2e\namneziawg-tools=3.1.20260812 commit=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'
printf '%s\n' "$expected_version" >"$bundle/awg-version"
if [[ -e /etc/hestia/.awg-runtime-version ]]; then
    [[ $(cat /etc/hestia/.awg-runtime-version) == "$expected_version" ]] || die "AWG version marker conflicts with the pinned package"
elif [[ -e /usr/local/lib/hestia/amneziawg-go || -e /usr/local/bin/awg || -e /etc/systemd/system/hestia-awg.service || -e /etc/tmpfiles.d/hestia-awg.conf || -e /etc/sudoers.d/hestia-awg ]]; then
    die "AWG files exist without a managed version marker"
fi
# shellcheck source=stage1-backend-credential.sh
source "$bundle/stage1-backend-credential.sh"
check_backend_credential "$bundle/stage1-backend-credential.dropin" || die "Unsafe or unsupported sing-box unit"
[[ ! -e /etc/systemd/system/hestia-smoke@.service ]] || cmp -s "$bundle/hestia-smoke@.service" /etc/systemd/system/hestia-smoke@.service || die "Conflicting smoke unit"
for pair in "hestia-awg@.service:$bundle/hestia-awg@.service:/etc/systemd/system/hestia-awg@.service" \
    "hestia-awg.conf:$bundle/hestia-awg.conf:/etc/tmpfiles.d/hestia-awg.conf" \
    "hestia-awg.sudoers:$bundle/hestia-awg.sudoers:/etc/sudoers.d/hestia-awg"; do
    IFS=: read -r _ src dst <<<"$pair"
    if [[ -e $dst ]] && ! cmp -s "$src" "$dst"; then
        previous=$(sha256sum "$dst" | cut -d' ' -f1)
        case "${dst##*/}:$previous" in
            hestia-awg:37a995b6c0e18a5484632aba75dbc06f3ae70c14f179c443ea069d5e51e69cfb | hestia-awg:28c185c8358527e7a51ea51dad3915e42cd70c58c3d207752ac078e72014b46b | hestia-awg:29ddb07c6d6ba99793c446d7c84dfac2c74d01433fd79de3a26c2d201de12873 | hestia-awg:91c7ec50424f8e4b912c7b39f0d8cd943eb67ac22b65430ca592d6525e2d32fb | hestia-awg:86585128891b44ea193e73fdce7aabdc3a55bf6691be90a1d8a948a706c5d4c5 | hestia-awg:7808b1b8fbc8d19d6b384cfc2c58371db9a8ae6988896d70521257e5e0d0dc36 | hestia-awg:413b8f66d5cb07de479e442e25677bf2652c72fd1eb01a186126d4f7e4115e63 | hestia-awg:781190ddbb01718b6e6463fc5460c0aa2e62f99f7343fe2acf9ae1eab8d7fb51 | hestia-awg.service:87c037de33a3e88565549f33dbc69410a38d3e2ed548d116d409e6397819a590 | hestia-awg.conf:29ef199c3a64383d0d883aa25c18f04200787c5715a9356e05902ef83ffbef27) ;;
            *) die "Unmanaged AWG configuration conflicts with package: $dst" ;;
        esac
    fi
done

for unit in hestia-binding-recovery.service hestia-binding-watch.path hestia-binding-watch.service; do
    path=/etc/systemd/system/$unit
    die_if_untrusted_file "$path"
    if [[ -e $path ]] && ! cmp -s "$bundle/$unit" "$path"; then
        previous=$(sha256sum "$path" | cut -d' ' -f1)
        case "$unit:$previous" in
            hestia-binding-watch.service:f6f721ec694af19997180094cabd2bf96fa530d0ff6559b6db3126315fa92078 | hestia-binding-recovery.service:449163cbc40901e498ba8a5de74ae893f1b6fa3f721ca5c0d577e5bab4492502) ;;
            *) die "Conflicting binding unit: $unit" ;;
        esac
    fi
done
die_if_untrusted_file /etc/tmpfiles.d/hestia-binding.conf
[[ ! -e /etc/tmpfiles.d/hestia-binding.conf ]] || cmp -s "$bundle/hestia-binding.conf" /etc/tmpfiles.d/hestia-binding.conf || die "Conflicting binding lock layout"

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
    /usr/local/lib/hestia/profile.py /usr/local/lib/hestia/smoke.py /usr/local/lib/hestia/amneziawg-go \
    /etc/hestia/.awg-runtime-version /etc/systemd/system/hestia.service \
    /etc/systemd/system/hestia-panel.service /etc/systemd/system/hestia-sing-box.service /etc/systemd/system/hestia-smoke@.service /etc/systemd/system/hestia-awg@.service \
    /etc/systemd/system/hestia-binding-{recovery.service,watch.path,watch.service} /etc/tmpfiles.d/hestia-binding.conf /etc/hestia/{sing-box.json,profile-backend.sha256} \
    /etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg; do
    die_if_untrusted_file "$path"
done

backup=/var/backups/hestia-stage1-awg-$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -e $backup && ! -L $backup ]] || die "Backup path already exists: $backup"
for path in /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/awg \
    /usr/local/lib/hestia/profile.py /usr/local/lib/hestia/smoke.py /usr/local/lib/hestia/amneziawg-go \
    /etc/hestia/.awg-runtime-version /etc/systemd/system/hestia.service \
    /etc/systemd/system/hestia-panel.service /etc/systemd/system/hestia-sing-box.service /etc/systemd/system/hestia-smoke@.service /etc/systemd/system/hestia-awg@.service \
    /etc/systemd/system/hestia-binding-{recovery.service,watch.path,watch.service} /etc/tmpfiles.d/hestia-binding.conf /etc/hestia/{sing-box.json,profile-backend.sha256} \
    /etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg \
    /usr/local/share/hestia-panel/current; do
    if [[ -e $path || -L $path ]]; then
        if [[ $path != */current ]]; then die_if_untrusted_file "$path"; fi
    fi
done

# All targets and parents are now preflighted; the following creates a manual recovery copy before replacing system files.
install -d -o root -g root -m 0700 "$backup"
install -d -o root -g root -m 0700 /etc/hestia/awg
cat >"$backup/README.txt" <<EOF
Manual backup created before the AWG stage1 update.

Before manual rollback stop the panel and binding watchdog, acquire /run/hestia-install.lock exclusively, then stop hestia.service and hestia-sing-box.service. Stop the named hestia-awg@ID.service instances. If reverting to the singleton, run the NEW /usr/local/bin/hestia -awg-retire ID 0 while the shared backend and named unit are stopped; verify its routes.json.ID manifest is absent before proceeding. If retirement fails, keep the dataplane stopped and investigate.
Restore the prior files and symlinks listed in manifest.txt from files/ to their original locations, remove targets listed in absent.txt, and reload systemd. If the old singleton was active in state.txt, start it and confirm readiness before releasing the installer lock. Restore the prior watchdog, routing and panel services after unlocking.

The backend drop-in $backend_dropin is added only if needed (added=$migrate_backend). Remove it during rollback only if added=1.
Targets absent from manifest.txt did not exist before this update. Remove those newly installed targets during manual rollback. They include the AWG runtime/tool/version marker, AWG systemd/tmpfiles/sudoers files, updated Hestia and panel binaries/units, and the panel current symlink. Also remove the newly installed browser release below only if no current symlink references it:
  $asset_release

Use state.txt and routes-before.txt to compare service and route state. This backup preserves the prior backend and checksum.
EOF
: >"$backup/manifest.txt"
: >"$backup/absent.txt"
for path in /usr/local/bin/hestia /usr/local/bin/hestia-panel /usr/local/bin/awg \
    /usr/local/lib/hestia/profile.py /usr/local/lib/hestia/smoke.py /usr/local/lib/hestia/amneziawg-go \
    /etc/hestia/.awg-runtime-version /etc/systemd/system/hestia.service \
    /etc/systemd/system/hestia-panel.service /etc/systemd/system/hestia-sing-box.service /etc/systemd/system/hestia-smoke@.service /etc/systemd/system/hestia-awg@.service \
    /etc/systemd/system/hestia-binding-{recovery.service,watch.path,watch.service} /etc/tmpfiles.d/hestia-binding.conf /etc/hestia/{sing-box.json,profile-backend.sha256} \
    /etc/tmpfiles.d/hestia-awg.conf /etc/sudoers.d/hestia-awg \
    /usr/local/share/hestia-panel/current; do
    if [[ -e $path || -L $path ]]; then
        name=${path#/}
        mkdir -p "$backup/files/$(dirname "$name")"
        cp -a -- "$path" "$backup/files/$name"
        printf '%s\n' "$path" >>"$backup/manifest.txt"
    else
        printf '%s\n' "$path" >>"$backup/absent.txt"
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

if ((adopt_profile == 0)); then
    python3 -I "$bundle/profile.py" --stage-awg-backend /etc/hestia "$build_dir"
fi
if [[ -f $build_dir/sing-box.json ]]; then
    /usr/local/lib/hestia/sing-box check -c "$build_dir/sing-box.json" >/dev/null
fi
ready_ids=
if ((adopt_profile == 0)); then
    ready_ids=$(python3 -I "$bundle/profile.py" --ready-awg /etc/hestia)
fi
named_activation=0
# restore_awg_upgrade reverts this upgrade before releasing the installer lock if a migrated runtime fails.
restore_awg_upgrade() {
    local status=$? path id
    set +e
    if ((status != 0)); then
        systemctl stop hestia-panel.service hestia.service hestia-sing-box.service
        if ((named_activation)); then
            while IFS= read -r id; do
                [[ -n $id ]] || continue
                systemctl stop "hestia-awg@${id}.service" || exit 1
                if ((legacy_awg_active)); then retire_migrated_awg "$bundle/hestia" "$id" || exit 1; fi
            done <<<"$ready_ids"
        fi
        while IFS= read -r path; do
            if [[ $path == /usr/local/share/hestia-panel/current && -d $backup/panel-current-directory ]]; then
                if [[ -L $path ]]; then unlink "$path"; fi
                if [[ ! -e $path ]]; then mv -T "$backup/panel-current-directory" "$path"; fi
            elif [[ $path != /usr/local/share/hestia-panel/current || ! -d $path || -L $path ]]; then
                cp -aT -- "$backup/files/${path#/}" "$path"
            fi
        done <"$backup/manifest.txt"
        while IFS= read -r path; do rm -f -- "$path"; done <"$backup/absent.txt"
        if ((migrate_backend)); then rm -f -- "$backend_dropin"; fi
        systemctl daemon-reload
        if ((legacy_awg_active)); then
            systemctl start hestia-awg.service
        elif [[ -f /etc/systemd/system/hestia-awg@.service ]]; then
            while IFS= read -r id; do
                [[ -z $id ]] || systemctl start "hestia-awg@${id}.service"
            done <<<"$ready_ids"
        fi
        flock -u 9
        systemctl start hestia-sing-box.service hestia.service hestia-panel.service
        echo "Restored prior gateway files; inspect runtime health and backup $backup" >&2
    fi
    rm -rf -- "$build_dir"
    exit "$status"
}
trap restore_awg_upgrade EXIT
drained=0
if ((legacy_awg_active)) || [[ -n $ready_ids ]]; then
    drained=1
    # Old runtimes tear down fail-closed guards only while the dataplane is stopped.
    systemctl stop hestia.service hestia-sing-box.service
fi
stop_legacy_awg "$bundle/hestia" "$ready_ids" || die "Could not retire legacy runtime"
if [[ -f $build_dir/sing-box.json ]]; then
    for name in sing-box.json profile-backend.sha256; do
        install -o root -g root -m 0600 "$build_dir/$name" "/etc/hestia/$name"
    done
fi
install -d -o root -g root -m 0755 /usr/local/share/hestia-panel/releases
if [[ ! -e $asset_release ]]; then
    install -d -o root -g root -m 0755 "$asset_release"
    cp -R "$bundle/browser/." "$asset_release/"
    chown -R root:root "$asset_release"
    chmod -R a-w,go+rX "$asset_release"
fi
if [[ -d /usr/local/share/hestia-panel/current && ! -L /usr/local/share/hestia-panel/current ]]; then
    mv -T /usr/local/share/hestia-panel/current "$backup/panel-current-directory"
fi
ln -s "releases/$asset_id" /usr/local/share/hestia-panel/current.next
mv -fT /usr/local/share/hestia-panel/current.next /usr/local/share/hestia-panel/current
install -o root -g root -m 0755 "$bundle/hestia" /usr/local/bin/hestia.next
mv -fT /usr/local/bin/hestia.next /usr/local/bin/hestia
install -o root -g root -m 0755 "$bundle/hestia-panel" /usr/local/bin/hestia-panel.next
mv -fT /usr/local/bin/hestia-panel.next /usr/local/bin/hestia-panel
install -o root -g root -m 0644 "$bundle/profile.py" /usr/local/lib/hestia/profile.py.next
mv -fT /usr/local/lib/hestia/profile.py.next /usr/local/lib/hestia/profile.py
install -o root -g root -m 0644 "$bundle/smoke.py" /usr/local/lib/hestia/smoke.py.next
mv -fT /usr/local/lib/hestia/smoke.py.next /usr/local/lib/hestia/smoke.py
install -o root -g root -m 0755 "$bundle/amneziawg-go" /usr/local/lib/hestia/amneziawg-go.next
mv -fT /usr/local/lib/hestia/amneziawg-go.next /usr/local/lib/hestia/amneziawg-go
install -o root -g root -m 0755 "$build_dir/src/wg" /usr/local/bin/awg.next
mv -fT /usr/local/bin/awg.next /usr/local/bin/awg
install -o root -g root -m 0600 "$bundle/awg-version" /etc/hestia/.awg-runtime-version
install -o root -g root -m 0644 "$bundle/hestia-smoke@.service" /etc/systemd/system/hestia-smoke@.service
install_backend_credential "$bundle/stage1-backend-credential.dropin"
install -o root -g root -m 0644 "$bundle/hestia-awg@.service" /etc/systemd/system/hestia-awg@.service
for unit in hestia-binding-recovery.service hestia-binding-watch.path hestia-binding-watch.service; do
    install -o root -g root -m 0644 "$bundle/$unit" "/etc/systemd/system/$unit"
done
install -o root -g root -m 0644 "$bundle/hestia-binding.conf" /etc/tmpfiles.d/hestia-binding.conf
install -o root -g root -m 0644 "$bundle/hestia-awg.conf" /etc/tmpfiles.d/hestia-awg.conf
install -o root -g root -m 0440 "$bundle/hestia-awg.sudoers" /etc/sudoers.d/hestia-awg
install -o root -g root -m 0644 "$build_dir/hestia-panel.service" /etc/systemd/system/hestia-panel.service
install -o root -g root -m 0644 "$bundle/hestia.service" /etc/systemd/system/hestia.service
visudo -cf /etc/sudoers.d/hestia-awg >/dev/null
systemctl daemon-reload
systemd-tmpfiles --create /etc/tmpfiles.d/hestia-awg.conf /etc/tmpfiles.d/hestia-binding.conf
/usr/local/bin/hestia -check -config /etc/hestia/snapshot.json
/usr/local/lib/hestia/sing-box check -c /etc/hestia/sing-box.json >/dev/null
python3 -I /usr/local/lib/hestia/profile.py --validate-managed /etc/hestia
named_activation=1
restart_ready_awg /usr/local/lib/hestia/profile.py || die "A committed connector failed its egress check; inspect backup $backup"
# The runtime and candidate were verified under the installer lock. Later checks use the manual backup.
trap 'rm -rf -- "$build_dir"' EXIT
flock -u 9
systemctl enable --now hestia-binding-watch.path
if ((drained || migrate_backend)) || [[ -f $build_dir/sing-box.json ]]; then systemctl restart hestia-sing-box.service; fi
systemctl restart hestia.service hestia-panel.service
confirm_manual_awg /usr/local/lib/hestia/profile.py
systemctl start hestia-smoke@current.service
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
if [[ -f $build_dir/sing-box.json ]]; then
    cmp "$build_dir/sing-box.json" /etc/hestia/sing-box.json
    diff <(grep -v ' /etc/hestia/sing-box.json$' "$hashes_before") <(grep -v ' /etc/hestia/sing-box.json$' "$backup/config-after.sha256")
else
    cmp -s "$hashes_before" "$backup/config-after.sha256" || die "WG-keenetic or profile/backend/snapshot bytes changed unexpectedly; inspect backup $backup"
fi
if [[ $(systemctl is-enabled hestia-awg.service 2>/dev/null || :) == enabled ]]; then
    systemctl disable hestia-awg.service
fi
echo "Stage1 package is installed. Manual backup of replaced files and service state: $backup"
