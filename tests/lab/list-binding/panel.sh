#!/usr/bin/env bash
# Start the tested panel binary under a dedicated, minimally privileged identity on the lab guest.
set -euo pipefail
[[ $(hostname -s) == lima-hestia-binding-test && $EUID == 0 && $# == 2 ]] || {
    echo "Usage on dedicated hestia-binding-test: sudo bash panel.sh PANEL_BINARY BROWSER_DIST" >&2
    exit 1
}
useradd --system --no-create-home --groups hestia-snapshot hestia-binding-panel
printf '%s\n' 'hestia-binding-panel ALL=(root) NOPASSWD: /usr/local/bin/hestia -apply-binding' >/etc/sudoers.d/hestia-binding-panel
chmod 0440 /etc/sudoers.d/hestia-binding-panel
visudo -cf /etc/sudoers.d/hestia-binding-panel
systemd-run --quiet --unit=hestia-binding-panel --uid=hestia-binding-panel \
    "$(realpath "$1")" -listen 127.0.0.1:18438 -snapshot /etc/hestia/snapshot.json \
    -assets "$(realpath "$2")" -enable-bindings
