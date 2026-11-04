#!/usr/bin/env bash
# Build and transfer the reviewed AWG panel/runtime bundle to the fixed stage1 Lima guest.
set -euo pipefail
umask 077
[[ $# == 0 ]] || {
    echo "Usage: bash deploy/stage1-awg-update.sh" >&2
    exit 2
}
repo=$(cd "$(dirname "$0")/.." && pwd)
instance=hestia-stage1
vm=${LIMACTL:-limactl}
go_version=1.27.3
awg_go_tag=v3.1.20260828
awg_go_commit=b5928efb6ca19f0153958460c3d141f04abc5c2e
awg_tools_tag=v3.1.20260812
awg_tools_commit=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
work=$(mktemp -d)
remote=

# guest runs one fixed read-only query on the named Lima VM and returns its output.
guest() {
    "$vm" shell "$instance" -- "$@"
}

# cleanup removes only this invocation's private staging package from the named VM and local temp directory.
cleanup() {
    if [[ $remote =~ ^/tmp/hestia-stage1-awg\.[A-Za-z0-9]+$ ]]; then
        guest sudo rm -rf -- "$remote" >/dev/null 2>&1 || :
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT

names=$("$vm" list --quiet)
grep -Fx "$instance" <<<"$names" >/dev/null || {
    echo "The existing Lima instance hestia-stage1 was not found; this script never creates or starts VMs." >&2
    exit 1
}
[[ $(guest hostname -s) == lima-hestia-stage1 ]] || {
    echo "Refusing a guest whose hostname is not lima-hestia-stage1" >&2
    exit 1
}
guest ip -4 -o addr show dev lima0 scope global |
    awk '$4 ~ /^192\.168\.1\.133\// { found=1 } END { exit !found }' || {
    echo "Refusing a guest without 192.168.1.133 on lima0" >&2
    exit 1
}
[[ $(go version) == "go version go$go_version darwin/arm64" ]] || {
    echo "Building the stage1 package requires Go $go_version on macOS ARM64" >&2
    exit 1
}

(cd "$repo" && GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -buildvcs=false -o "$work/hestia" ./cmd/hestia)
(cd "$repo" && GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -buildvcs=false -o "$work/hestia-panel" ./cmd/hestia-panel)
(cd "$repo/frontend" && npm ci && npm run build -- --output-path "$work/frontend-build")
mv "$work/frontend-build/browser" "$work/browser"

git clone --depth 1 --branch "$awg_go_tag" \
    https://github.com/amnezia-vpn/amneziawg-go.git "$work/amneziawg-go-source"
[[ $(git -C "$work/amneziawg-go-source" rev-parse HEAD) == "$awg_go_commit" ]] || {
    echo "Unexpected amneziawg-go source revision" >&2
    exit 1
}
(
    cd "$work/amneziawg-go-source"
    GOENV=off GOTOOLCHAIN=local GOWORK=off GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
        GOFLAGS='-trimpath -buildvcs=false' make generate-version-and-build
)
install -m 0755 "$work/amneziawg-go-source/amneziawg-go" "$work/amneziawg-go"

git clone --depth 1 --branch "$awg_tools_tag" \
    https://github.com/amnezia-vpn/amneziawg-tools.git "$work/amneziawg-tools-source"
[[ $(git -C "$work/amneziawg-tools-source" rev-parse HEAD) == "$awg_tools_commit" ]] || {
    echo "Unexpected amneziawg-tools source revision" >&2
    exit 1
}
git -C "$work/amneziawg-tools-source" archive --format=tar HEAD >"$work/amneziawg-tools-source.tar"

cp "$repo/deploy/stage1-awg-apply.sh" "$work/"
cp "$repo/deploy/profile.py" "$work/"
cp "$repo/deploy/systemd/hestia.service" "$work/"
cp "$repo/deploy/systemd/hestia-awg.service" "$work/"
cp "$repo/deploy/systemd/hestia-awg.conf" "$work/"
cp "$repo/deploy/systemd/hestia-awg.sudoers" "$work/"
cp "$repo/deploy/systemd/hestia-panel.service.in" "$work/"
(cd "$work" && shasum -a 256 hestia hestia-panel amneziawg-go amneziawg-tools-source.tar >SHA256SUMS)
COPYFILE_DISABLE=1 tar -C "$work" -czf "$work/stage1-awg-update.tgz" \
    hestia hestia-panel browser amneziawg-go amneziawg-tools-source.tar SHA256SUMS \
    stage1-awg-apply.sh profile.py hestia.service hestia-awg.service \
    hestia-awg.conf hestia-awg.sudoers hestia-panel.service.in

remote=$(guest mktemp -d /tmp/hestia-stage1-awg.XXXXXXXX)
[[ $remote =~ ^/tmp/hestia-stage1-awg\.[A-Za-z0-9]+$ ]] || {
    echo "Guest returned an unsafe staging path" >&2
    exit 1
}
"$vm" copy "$work/stage1-awg-update.tgz" "$instance:$remote/package.tgz"
guest tar -C "$remote" -xzf "$remote/package.tgz"
guest sudo bash "$remote/stage1-awg-apply.sh" "$remote"
echo "Stage1 AWG package applied. The script did not alter the router, WireGuard profile, or main route."
