#!/usr/bin/env bash
# Validate privileged application paths before a deployment changes them.

# die reports a rejected trusted-path invariant.
die() {
    echo "$*" >&2
    exit 1
}

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

# stop_existing_units ignores only verified absent units and fails any loaded-unit stop error.
stop_existing_units() {
    local unit state
    for unit in "$@"; do
        state=$(systemctl show --property=LoadState --value "$unit") || return 1
        if [[ $state == not-found ]]; then continue; fi
        [[ -n $state ]] || return 1
        systemctl stop "$unit" || return 1
    done
}

# route_snapshot retains one-line main-table records and canonicalizes independent destinations; capture or normalization errors fail the caller.
route_snapshot() {
    local family=$1 output=$2
    [[ $family == 4 || $family == 6 ]] || return 1
    ip -o "-$family" route show table main >"$output" || return 1
    python3 -I - "$output" <<'PY'
import ipaddress
from pathlib import Path
import sys


def route_key(row: str) -> tuple[str, str]:
    """Order independent destinations, preserving competing routes and nexthops."""
    tokens = row.split()
    if not tokens:
        raise ValueError('Empty route record')
    kinds = {'unicast', 'local', 'broadcast', 'multicast', 'throw',
             'unreachable', 'prohibit', 'blackhole', 'nat', 'anycast'}
    destination = tokens[1] if tokens[0] in kinds else tokens[0]
    if destination == 'default':
        return destination, ''
    network = ipaddress.ip_network(destination, strict=False)
    # IPv6 link-local direct routes apply independently on each device.
    # Other equal destinations retain their original order conservatively.
    device = ''
    if network.version == 6 and network.is_link_local and 'via' not in tokens and 'nexthop' not in tokens:
        device = tokens[tokens.index('dev') + 1]
    return str(network), device


source = Path(sys.argv[1])
rows = source.read_text().splitlines(keepends=True)
if any(not row.endswith('\n') for row in rows):
    raise ValueError('Incomplete route record')
source.with_name(source.name + '.canonical').write_text(''.join(sorted(rows, key=route_key)))
PY
}
