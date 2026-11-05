#!/usr/bin/env bash
# Run on the MacBook from a trusted checkout with Lima, Go and Node.js installed.
set -euo pipefail
umask 077
[[ $# == 2 ]] || {
    echo "usage: $0 {start|install|update|export-peer} INSTANCE" >&2
    exit 2
}
action=$1
instance=$2
[[ $instance =~ ^[a-z][a-z0-9-]{0,50}$ && $instance != hestia-stage1 && $instance != hestia-test-client ]] ||
    {
        echo "Choose a separate lab instance name" >&2
        exit 2
    }
vm=${LIMACTL:-limactl}
dir=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$dir/../.." && pwd)

# guest sends the supplied argument vector to this named Lima guest; it returns the guest command's status and output.
guest() {
    "$vm" shell "$instance" -- "$@"
}

# export_peer copies the guest peer profile to the private project directory with mode 0600; it fails on unsafe paths or a conflicting existing profile.
export_peer() {
    local dest profile_tmp dir_mode
    dest="$repo/private/$instance-keenetic.conf"
    [[ ! -L $repo/private && ! -L $dest && (! -e $dest || -f $dest) ]] ||
        {
            echo "Unsafe private profile path" >&2
            return 1
        }
    mkdir -p "$repo/private"
    dir_mode=$(stat -f '%Lp' "$repo/private")
    if [[ ! -O $repo/private ]] || (((8#$dir_mode & 022) != 0)); then
        echo "Private directory must belong to you and only be writable by you" >&2
        return 1
    fi
    if [[ -e $dest ]]; then
        [[ -O $dest && $(stat -f '%Lp' "$dest") == 600 ]] ||
            {
                echo "Existing profile must belong to you and have mode 0600" >&2
                return 1
            }
    fi
    profile_tmp=$(mktemp "$repo/private/.scheme3-XXXXXX")
    if ! guest sudo cat /etc/hestia-scheme3/hestia-keenetic.conf >"$profile_tmp" || [[ ! -s $profile_tmp ]]; then
        rm -f "$profile_tmp"
        return 1
    fi
    if ! ln "$profile_tmp" "$dest" && ! cmp -s "$profile_tmp" "$dest"; then
        rm -f "$profile_tmp"
        echo "Preserved differing existing profile: $dest" >&2
        return 1
    fi
    chmod 0600 "$dest"
    rm -f "$profile_tmp"
    echo "Keenetic profile: $dest"
}

case $action in
    start)
        names=$("$vm" list --quiet)
        if grep -Fx "$instance" <<<"$names" >/dev/null; then
            "$vm" start "$instance"
        else
            "$vm" start --name="$instance" --tty=false "$dir/host-lima.yaml"
        fi
        guest ip -4 -br address show lima0
        exit
        ;;
    export-peer)
        export_peer
        exit
        ;;
    install | update) ;;
    *)
        echo "Unknown operation: $action" >&2
        exit 2
        ;;
esac

work=$(mktemp -d)
remote=
# build_awg_runtime verifies upstream commits and the fixed host Go toolchain before building Linux ARM64 artifacts.
build_awg_runtime() {
    local output=$1 source tools_source awg_go_commit awg_tools_commit
    local awg_go_tag=3.1.20260828 awg_tools_tag=v3.1.20260812
    awg_go_commit=b5928efb6ca19f0153958460c3d141f04abc5c2e
    awg_tools_commit=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
    source="$output/amneziawg-go-source"
    tools_source="$output/amneziawg-tools-source"

    git clone --depth 1 --branch "v$awg_go_tag" \
        https://github.com/amnezia-vpn/amneziawg-go.git "$source"
    [[ $(git -C "$source" rev-parse HEAD) == "$awg_go_commit" ]] || {
        echo "Unexpected amneziawg-go source revision" >&2
        return 1
    }
    (
        cd "$source"
        GOENV=off GOTOOLCHAIN=local GOWORK=off GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOFLAGS='-trimpath -buildvcs=false' \
            make generate-version-and-build
    )
    install -m 0755 "$source/amneziawg-go" "$output/amneziawg-go"

    git clone --depth 1 --branch "$awg_tools_tag" \
        https://github.com/amnezia-vpn/amneziawg-tools.git "$tools_source"
    [[ $(git -C "$tools_source" rev-parse HEAD) == "$awg_tools_commit" ]] || {
        echo "Unexpected amneziawg-tools source revision" >&2
        return 1
    }
    git -C "$tools_source" archive --format=tar HEAD >"$output/amneziawg-tools-source.tar"
    (cd "$output" && shasum -a 256 amneziawg-go amneziawg-tools-source.tar >awg-SHA256SUMS)
}

# cleanup removes this invocation's private transfer directory and local build tree; it does not alter VM configuration.
cleanup() {
    if [[ $remote =~ ^/tmp/hestia-s3\.[a-zA-Z0-9]+$ ]]; then guest sudo rm -rf -- "$remote" || :; fi
    rm -rf -- "$work"
}
trap cleanup EXIT
remote=$(guest mktemp -d /tmp/hestia-s3.XXXXXXXX)
[[ $remote =~ ^/tmp/hestia-s3\.[a-zA-Z0-9]+$ ]]
cd "$repo"
[[ $(GOENV=off GOTOOLCHAIN=local go env GOVERSION) == go1.27.3 ]] || {
    echo "Building Hestia and AmneziaWG requires Go 1.27.3" >&2
    exit 1
}
for name in hestia hestia-panel; do
    GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go -C backend build -trimpath -o "$work/$name" "./cmd/$name"
done
build_awg_runtime "$work"
mkdir "$work/frontend"
tar -C frontend --exclude node_modules --exclude dist --exclude .angular -cf - . | tar -C "$work/frontend" -xf -
(cd "$work/frontend" && npm ci && npm run build -- --output-path "$work/ui")
mv "$work/ui/browser" "$work/browser"
cp -R "$dir" "$work/scheme3"
cp "$repo/deploy/awg-upgrade.sh" "$repo/deploy/profile.py" "$repo/deploy/smoke.py" "$work/scheme3/"
for unit in hestia-smoke@.service hestia-binding-recovery.service hestia-binding-watch.path hestia-binding-watch.service hestia-binding.conf; do
    cp "$repo/deploy/systemd/$unit" "$work/scheme3/$unit"
done
cp "$repo/deploy/systemd/hestia-awg@.service" "$work/scheme3/"
cp "$repo/deploy/systemd/hestia-awg.conf" "$work/scheme3/hestia-awg.tmpfiles"
mkdir -p "$work/deploy" "$work/backend/internal/geoip"
mkdir -p "$work/deploy/systemd"
cp "$repo/deploy/systemd/"hestia-geoip-publish.{service,timer} "$work/deploy/systemd/"
cp -R "$repo/deploy/geoip" "$work/deploy/"
cp "$repo/deploy/"{geoip-install.sh,import_geoip.py,publish_geoip.py} "$work/deploy/"
cp "$repo/backend/internal/geoip/countries.txt" "$work/backend/internal/geoip/"
files=(deploy backend scheme3 hestia hestia-panel browser amneziawg-go amneziawg-tools-source.tar awg-SHA256SUMS)
if [[ $action == install ]]; then
    release=sing-box-1.14.4-linux-arm64
    if [[ -n ${SING_BOX_ARCHIVE:-} ]]; then
        cp "$SING_BOX_ARCHIVE" "$work/sing.tgz"
    else
        curl --fail --location --proto '=https' --proto-redir '=https' --output "$work/sing.tgz" \
            "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/$release.tar.gz"
    fi
    (cd "$work" && shasum -a 256 -c "$repo/deploy/sing-box-1.14.4-linux-arm64.sha256")
    tar -C "$work" -xzf "$work/sing.tgz" "$release/sing-box"
    mv "$work/$release/sing-box" "$work/sing-box"
    files+=(sing-box)
fi
COPYFILE_DISABLE=1 tar -C "$work" -czf "$work/bundle.tgz" "${files[@]}"
"$vm" copy "$work/bundle.tgz" "$instance:$remote/bundle.tgz"
guest tar -C "$remote" -xzf "$remote/bundle.tgz"
guest sudo bash "$remote/scheme3/host-apply.sh" "$action" "$remote"
if [[ $action == install ]]; then export_peer; fi
