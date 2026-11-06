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
