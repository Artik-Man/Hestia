#!/usr/bin/env bash
# Install from a trusted Hestia checkout on Debian ARM64 with systemd.
set -euo pipefail
umask 077
repo=$(cd "$(dirname "$0")/.." && pwd)
sing_version=1.14.4
sing_sha=436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26
go_version=1.27.3
go_sha=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49
controller=
archive=
profile=
# usage prints the supported installation arguments without changing the host.
usage() {
    echo "Usage: sudo bash deploy/install.sh [--config FILE] [--controller-binary TRUSTED_LINUX_ARM64_FILE] [--sing-box-archive FILE]"
}
# die reports the supplied installation error on stderr and exits with a nonzero status.
die() {
    echo "Hestia: $*" >&2
    exit 1
}
while (($#)); do
    case $1 in
        -h | --help)
            usage
            exit 0
            ;;
        --config | --controller-binary | --sing-box-archive)
            [[ $# -ge 2 && -f $2 ]] || die "$1 requires an existing file"
            case $1 in
                --config) profile=$(realpath "$2") ;;
                --controller-binary) controller=$(realpath "$2") ;;
                --sing-box-archive) archive=$(realpath "$2") ;;
            esac
            shift 2
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done
[[ $EUID == 0 ]] || die "run as root"
[[ -r /etc/os-release ]] || die "Debian ARM64 required"
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == debian && $(dpkg --print-architecture) == arm64 && -d /run/systemd/system ]] ||
    die "requires Debian ARM64 running systemd as PID 1"
exec 9>/run/hestia-install.lock
flock -n 9 || die "another Hestia configuration update is running"
[[ ! -e /etc/hestia/.binding-pending && ! -L /etc/hestia/.binding-pending ]] || die "recover the pending binding update before installing"
work=$(mktemp -d)
managed=()
had_group=1
transaction=0
services=(hestia-sing-box.service hestia.service)
managed_units=(hestia-binding-recovery.service hestia-binding-watch.path hestia-binding-watch.service "${services[@]}")
declare -A enabled active
# cleanup rolls back replaced files and service states after a failed transaction and removes temporary artifacts.
cleanup() {
    local rc=$? i file unit
    trap - EXIT INT TERM
    if ((rc != 0 && transaction)); then
        set +e
        echo "Installation failed; restoring previous Hestia files and service states." >&2
        systemctl stop hestia.service hestia-sing-box.service hestia-binding-watch.path hestia-binding-watch.service hestia-binding-recovery.service >/dev/null 2>&1
        systemctl disable hestia.service hestia-sing-box.service hestia-binding-watch.path >/dev/null 2>&1
        for ((i = ${#managed[@]} - 1; i >= 0; i--)); do
            file=${managed[i]}
            if [[ -e $work/backup-$i ]]; then cp -a --remove-destination "$work/backup-$i" "$file"; else rm -f -- "$file"; fi
        done
        systemctl daemon-reload
        for unit in "${managed_units[@]}"; do
            if [[ ${enabled[$unit]} == enabled ]]; then systemctl enable "$unit"; fi
            # The path unit starts its one-shot worker; never wait for that worker under the installer lock.
            if [[ ${active[$unit]} == active && $unit != hestia-binding-watch.service ]]; then systemctl start "$unit"; fi
        done
        if ((had_group == 0)); then
            chown root:root /run/hestia-install.lock
            chmod 0600 /run/hestia-install.lock
            groupdel hestia-snapshot
        fi
    fi
    rm -rf -- "$work"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
missing=()
for dependency in 'curl:curl' 'ss:iproute2' 'python3:python3'; do
    command -v "${dependency%%:*}" >/dev/null || missing+=("${dependency#*:}")
done
[[ -f /etc/ssl/certs/ca-certificates.crt ]] || missing+=(ca-certificates)
if ((${#missing[@]})); then
    apt-get update -o APT::Update::Error-Mode=any
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi
# fetch downloads the specified HTTPS artifact to the supplied staging path, enforcing HTTPS redirects.
fetch() {
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --retry 2 --output "$2" "$1"
}
# check_hash compares a staged archive with its pinned SHA-256 digest before extraction.
check_hash() {
    echo "$1  $2" | sha256sum -c -
}
if [[ -z $controller ]]; then
    fetch "https://go.dev/dl/go$go_version.linux-arm64.tar.gz" "$work/go.tgz"
    check_hash "$go_sha" "$work/go.tgz"
    tar -C "$work" -xzf "$work/go.tgz"
    (cd "$repo" && GOENV=off GOTOOLCHAIN=local GOWORK=off GOPROXY=off CGO_ENABLED=0 \
        GOCACHE="$work/cache" "$work/go/bin/go" build -mod=readonly -trimpath -buildvcs=false -o "$work/hestia" ./cmd/hestia)
else
    install -m 0755 "$controller" "$work/hestia"
fi
if [[ -z $archive ]]; then
    fetch "https://github.com/SagerNet/sing-box/releases/download/v$sing_version/sing-box-$sing_version-linux-arm64.tar.gz" "$work/sing.tgz"
else
    cp -- "$archive" "$work/sing.tgz"
fi
check_hash "$sing_sha" "$work/sing.tgz"
member=sing-box-$sing_version-linux-arm64/sing-box
tar -C "$work" -xzf "$work/sing.tgz" "$member"
backend=$work/$member
config=/etc/hestia
marker=$config/.installer-managed
# check_directory rejects symlinked or untrusted writable destination directories before installing as root.
check_directory() {
    local dir=$1 mode gid
    if [[ ! -e $dir && ! -L $dir ]]; then return; fi
    [[ -d $dir && ! -L $dir && $(stat -c %u "$dir") == 0 ]] || die "unsafe destination directory: $dir"
    mode=$(stat -c %a "$dir")
    gid=$(stat -c %g "$dir")
    (((8#$mode & 2) == 0)) || die "world-writable destination directory: $dir"
    if (((8#$mode & 16) != 0 && gid != 0)); then
        # Debian commonly grants write to an empty staff group under /usr/local.
        [[ -z $(getent group "$gid" | cut -d: -f4) &&
        -z $(getent passwd | awk -F: -v g="$gid" '$4==g && $3!=0 {print $1}') ]] ||
            die "non-root users can write destination directory: $dir"
    fi
}
for dir in /usr/local /usr/local/lib /usr/local/lib/hestia /usr/local/bin /etc/systemd/system /etc/systemd/system/hestia.service.d /etc/tmpfiles.d "$config"; do
    check_directory "$dir"
done
for file in "$marker" "$config/snapshot.json" "$config/sing-box.json" "$config/profile.json" "$config/profile-backend.sha256" "$config/profile-source.sha256"; do
    if [[ -e $file || -L $file ]]; then
        [[ -f $file && ! -L $file && $(stat -c %u "$file") == 0 ]] || die "unsafe configuration path: $file"
        file_mode=$(stat -c %a "$file")
        (((8#$file_mode & 18) == 0)) || die "writable by non-root: $file"
        if [[ $file == "$config/sing-box.json" ]]; then
            (((8#$file_mode & 077) == 0)) || die "backend configuration contains secrets and must be root-only (chmod 600): $file"
        fi
    fi
done
if [[ ! -f $marker ]]; then
    for file in "$config"/{profile.json,profile-backend.sha256,profile-source.sha256}; do
        [[ ! -e $file ]] || die "profile metadata exists outside this installer: $file"
    done
fi
stage=$work/config
mkdir "$stage"
if [[ -n $profile ]]; then
    install -m 0600 "$profile" "$work/profile.json"
    python3 "$repo/deploy/profile.py" "$work/profile.json" "$stage" "$(dirname "$profile")"
    sha256sum "$stage/sing-box.json" | cut -d" " -f1 >"$work/profile-backend.sha256"
    sha256sum "$work/profile.json" | cut -d" " -f1 >"$work/profile-source.sha256"
else
    for name in snapshot.json sing-box.json; do
        if [[ -f $config/$name ]]; then
            cp -- "$config/$name" "$stage/$name"
        else
            cp -- "$repo/deploy/bootstrap/$name" "$stage/$name"
        fi
    done
fi
"$work/hestia" -check -config "$stage/snapshot.json"
if ! "$backend" check -c "$stage/sing-box.json" >"$work/backend-check.log" 2>&1; then
    die "sing-box rejected the candidate config; check the supplied profile locally (details suppressed to protect credentials)"
fi
for unit in "${managed_units[@]}"; do
    enabled[$unit]=$(systemctl is-enabled "$unit" 2>/dev/null || :)
    active[$unit]=$(systemctl is-active "$unit" 2>/dev/null || :)
    case ${enabled[$unit]} in enabled | disabled | static | not-found | '') ;; *) die "$unit has unsupported pre-existing enablement: ${enabled[$unit]}" ;; esac
    if [[ ! -f $marker && $(systemctl show "$unit" -p FragmentPath --value) != "" ]]; then
        die "$unit already exists outside this installer; migrate it explicitly"
    fi
done
# owned_socket allows an empty API port or the loopback socket owned by the previously managed backend.
owned_socket() {
    local sockets pid
    sockets=$(ss -H -ltnp 'sport = :9090')
    [[ -z $sockets ]] && return 0
    pid=$(systemctl show -p MainPID --value hestia-sing-box.service)
    [[ -f $marker && $pid != 0 && $sockets != *$'\n'* && $sockets == *"127.0.0.1:9090"* && $sockets == *"pid=$pid,"* ]]
}
owned_socket || die "port 9090 is occupied by another service"
for file in /usr/local/bin/hestia /usr/local/lib/hestia/sing-box /usr/local/bin/hestia-export-config /usr/local/lib/hestia/profile.py /usr/local/lib/hestia/smoke.py /etc/tmpfiles.d/hestia-binding.conf /usr/local/lib/hestia/hestia-observe.service; do
    [[ -f $marker || ! -e $file ]] || die "$file exists outside this installer"
done
# replace backs up the destination, prepares a same-directory file with the requested permissions, then atomically renames it.
replace() {
    local src=$1 dst=$2 mode=$3 group=${4:-root} index=${#managed[@]} temp
    if [[ -e $dst ]]; then
        [[ -f $dst && ! -L $dst ]] || die "unexpected managed path: $dst"
        cp -a -- "$dst" "$work/backup-$index"
    fi
    managed+=("$dst")
    temp=$(mktemp "${dst}.install.XXXXXX")
    install -m "$mode" -o root -g "$group" "$src" "$temp"
    mv -fT -- "$temp" "$dst"
}
transaction=1
if ! getent group hestia-snapshot >/dev/null; then
    groupadd --system hestia-snapshot
    had_group=0
fi
chown root:hestia-snapshot /run/hestia-install.lock
chmod 0640 /run/hestia-install.lock
for dir in /usr/local/bin /usr/local/lib/hestia /etc/systemd/system/hestia.service.d /etc/tmpfiles.d; do
    if [[ ! -d $dir ]]; then install -d -m 0755 "$dir"; fi
done
if [[ ! -d $config ]]; then install -d -m 0751 "$config"; fi
if [[ ${active[hestia.service]} == active ]]; then systemctl stop hestia.service; fi
if [[ -n $profile ]]; then
    replace "$work/profile.json" "$config/profile.json" 0600
    replace "$work/profile-backend.sha256" "$config/profile-backend.sha256" 0600
    replace "$work/profile-source.sha256" "$config/profile-source.sha256" 0600
fi
for name in snapshot.json sing-box.json; do
    if [[ -n $profile || ! -f $config/$name ]]; then
        if [[ $name == snapshot.json ]]; then
            replace "$stage/$name" "$config/$name" 0640 hestia-snapshot
        else replace "$stage/$name" "$config/$name" 0600; fi
    fi
done
replace "$work/hestia" /usr/local/bin/hestia 0755
replace "$repo/deploy/export-config.py" /usr/local/bin/hestia-export-config 0755
replace "$repo/deploy/profile.py" /usr/local/lib/hestia/profile.py 0644
replace "$repo/deploy/smoke.py" /usr/local/lib/hestia/smoke.py 0644
replace "$repo/deploy/systemd/hestia-binding.conf" /etc/tmpfiles.d/hestia-binding.conf 0644
replace "$repo/deploy/systemd/hestia-observe.service" /usr/local/lib/hestia/hestia-observe.service 0644
replace "$backend" /usr/local/lib/hestia/sing-box 0755
for unit in "${managed_units[@]}"; do replace "$repo/deploy/systemd/$unit" "/etc/systemd/system/$unit" 0644; done
replace "$repo/deploy/systemd/hestia.service.d/backend.conf" /etc/systemd/system/hestia.service.d/backend.conf 0644
echo 1 >"$work/marker"
replace "$work/marker" "$marker" 0600
systemctl daemon-reload
systemctl enable hestia-binding-watch.path "${services[@]}"
systemctl stop hestia.service
systemctl restart hestia-binding-watch.path
systemctl restart hestia-sing-box.service
systemctl start hestia.service
start=$SECONDS
echo "Running installation smoke check (six-second total timeout)..."
if ! timeout 6s python3 "$repo/deploy/smoke.py"; then
    echo "Health check failed. Inspect journalctl -u hestia -u hestia-sing-box." >&2
    exit 1
fi
echo "Hestia installed; smoke check passed in $((SECONDS - start)) s."
