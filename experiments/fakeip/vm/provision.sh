#!/usr/bin/env bash
# Installs the lab tools inside the disposable Debian ARM64 guest.
set -euo pipefail

[[ $EUID == 0 && $(dpkg --print-architecture) == arm64 && -c /dev/net/tun ]] || {
    echo "Expected root on Debian ARM64 with /dev/net/tun" >&2
    exit 1
}
[[ $# == 1 && -f $1 ]] || { echo "Usage: provision.sh PATH_TO_SING_BOX_ARCHIVE" >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cp -- "$1" "$tmp/sing-box.tar.gz"
cd "$tmp"
echo '436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26  sing-box.tar.gz' | sha256sum -c -
member=sing-box-1.14.4-linux-arm64/sing-box
tar -xzf sing-box.tar.gz "$member"

missing=()
for package in bash iproute2 procps tcpdump python3; do
    if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true) != 'install ok installed' ]]; then
        missing+=("$package")
    fi
done
if (( ${#missing[@]} )); then
    apt-get update -o APT::Update::Error-Mode=any
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi

target=/usr/local/bin/sing-box
if ! cmp -s "$member" "$target"; then
    install -m 755 "$member" "$target"
fi
"$target" version
