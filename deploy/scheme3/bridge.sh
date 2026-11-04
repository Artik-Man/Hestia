#!/usr/bin/env bash
# Prepare socket_vmnet and the Lima sudoers include on an Apple Silicon Mac.
set -euo pipefail
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]]
[[ $EUID != 0 ]] || {
    echo "Run as your normal Mac user." >&2
    exit 1
}
lima=${LIMACTL:-limactl}
command -v "$lima" >/dev/null
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
if [[ ! -x /opt/socket_vmnet/bin/socket_vmnet ]]; then
    git clone --depth 1 --branch v1.2.2 https://github.com/lima-vm/socket_vmnet.git "$work/src"
    make -C "$work/src"
    sudo make -C "$work/src" PREFIX=/opt/socket_vmnet install.bin
fi
"$lima" sudoers >"$work/lima"
[[ -s $work/lima ]]
sudo visudo -cf "$work/lima"
target=/private/etc/sudoers.d/lima
if [[ -e $target ]]; then
    "$lima" sudoers --check "$target" || {
        echo "Review the existing $target before replacing it." >&2
        exit 1
    }
else
    sudo install -o root -g wheel -m 0444 "$work/lima" "$target"
fi
"$lima" sudoers --check "$target"
