#!/usr/bin/env bash
# Run inside the guest as a normal user with sudo for installation only.
set -euo pipefail
archive=${1:?pass the accel-ppp 1.15.0 release archive}
archive=$(realpath "$archive")
build=$(mktemp -d)
trap 'rm -rf -- "$build"' EXIT
cd "$build"
echo "408a7c02d25633ee2370887b67338c722858548d5431a7490c2af7774856e279  $archive" | sha256sum -c -
tar --extract --gzip --file="$archive" --no-same-owner
cmake -S accel-ppp-1.15.0 -B build -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
sudo cmake --install build
