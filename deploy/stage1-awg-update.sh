#!/usr/bin/env bash
# Build and transfer the reviewed AWG panel/runtime bundle to the fixed hestia-prod Lima guest.
set -euo pipefail
umask 077
[[ $# == 0 || ($# == 1 && $1 == --fresh) ]] || {
    echo "Usage: bash deploy/stage1-awg-update.sh [--fresh]" >&2
    exit 2
}
repo=$(cd "$(dirname "$0")/.." && pwd)
instance=hestia-prod
apply=stage1-awg-apply.sh
extra=(hestia-dns.service hestia-binding.conf hestia-binding-recovery.service hestia-binding-watch.path hestia-binding-watch.service)
if [[ ${1:-} == --fresh ]]; then
    apply=stage1-fresh-apply.sh
    runtime=/private/tmp/hestia-vm-run
    if [[ -d $runtime/lima-state/hestia-prod ]]; then
        export LIMA_HOME=${LIMA_HOME:-$runtime/lima-state}
        LIMACTL=${LIMACTL:-$runtime/bin/limactl}
    fi
fi
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
    if [[ $remote =~ ^/tmp/hestia-prod-awg\.[A-Za-z0-9]+$ ]]; then
        guest sudo rm -rf -- "$remote" >/dev/null 2>&1 || :
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT

names=$("$vm" list --quiet)
grep -Fx "$instance" <<<"$names" >/dev/null || {
    echo "The existing Lima instance hestia-prod was not found; this script never creates or starts VMs." >&2
    exit 1
}
[[ $(guest hostname -s) == lima-hestia-prod ]] || {
    echo "Refusing a guest whose hostname is not lima-hestia-prod" >&2
    exit 1
}
guest ip -4 -o addr show dev lima0 scope global |
    awk '$4 ~ /^192\.168\.1\.133\// { found=1 } END { exit !found }' || {
    echo "Refusing a guest without 192.168.1.133 on lima0" >&2
    exit 1
}
[[ $(GOENV=off GOTOOLCHAIN=local go env GOVERSION) == "go$go_version" ]] || {
    echo "Building the stage1 package requires Go $go_version" >&2
    exit 1
}

(cd "$repo/backend" && GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -buildvcs=false -o "$work/hestia" ./cmd/hestia)
(cd "$repo/backend" && GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
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

mkdir -p "$work/deploy" "$work/backend/internal/geoip"
mkdir -p "$work/deploy/systemd"
cp "$repo/deploy/systemd/"hestia-geoip-publish.{service,timer} "$work/deploy/systemd/"
cp -R "$repo/deploy/geoip" "$work/deploy/"
cp "$repo/deploy/"{geoip-install.sh,import_geoip.py,publish_geoip.py} "$work/deploy/"
cp "$repo/backend/internal/geoip/countries.txt" "$work/backend/internal/geoip/"
cp "$repo/deploy/$apply" "$work/"
for unit in ${extra[@]+"${extra[@]}"}; do cp "$repo/deploy/systemd/$unit" "$work/"; done
cp "$repo/deploy/awg-upgrade.sh" "$repo/deploy/profile.py" "$repo/deploy/smoke.py" "$work/"
cp "$repo/deploy/systemd/hestia-smoke@.service" "$work/"
cp "$repo/deploy/stage1-backend-credential.sh" "$repo/deploy/stage1-backend-credential.dropin" "$work/"
cp "$repo/deploy/scheme3/adopt-profile.py" "$work/"
cp "$repo/deploy/scheme3/guest-profile.json" "$work/"
cp "$repo/deploy/systemd/hestia.service" "$work/"
cp "$repo/deploy/systemd/hestia-awg@.service" "$work/"
cp "$repo/deploy/systemd/hestia-awg.conf" "$work/"
cp "$repo/deploy/systemd/hestia-awg.sudoers" "$work/"
cp "$repo/deploy/systemd/hestia-panel.service.in" "$work/"
(cd "$work" && shasum -a 256 hestia hestia-panel amneziawg-go amneziawg-tools-source.tar hestia-dns.service >SHA256SUMS)
COPYFILE_DISABLE=1 tar -C "$work" -czf "$work/stage1-awg-update.tgz" \
    deploy backend hestia hestia-panel browser amneziawg-go amneziawg-tools-source.tar SHA256SUMS \
    "$apply" ${extra[@]+"${extra[@]}"} awg-upgrade.sh profile.py smoke.py adopt-profile.py guest-profile.json hestia.service stage1-backend-credential.sh stage1-backend-credential.dropin hestia-smoke@.service hestia-awg@.service \
    hestia-awg.conf hestia-awg.sudoers hestia-panel.service.in

remote=$(guest mktemp -d /tmp/hestia-prod-awg.XXXXXXXX)
[[ $remote =~ ^/tmp/hestia-prod-awg\.[A-Za-z0-9]+$ ]] || {
    echo "Guest returned an unsafe staging path" >&2
    exit 1
}
"$vm" copy "$work/stage1-awg-update.tgz" "$instance:$remote/package.tgz"
guest tar -C "$remote" -xzf "$remote/package.tgz"
guest sudo chown -R root:root -- "$remote"
guest sudo chmod -R go-w -- "$remote"
guest sudo chmod 0700 -- "$remote"
guest sudo bash "$remote/$apply" "$remote"
echo "Stage1 AWG package applied. The script did not alter the router, WireGuard profile, or main route."
