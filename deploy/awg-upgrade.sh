#!/usr/bin/env bash
# Source in trusted gateway installers under their installation lock.

# inspect_legacy_awg verifies an existing singleton unit before migration and records its active state.
inspect_legacy_awg() {
    local path=/etc/systemd/system/hestia-awg.service state hash
    legacy_awg_active=0
    if [[ ! -e $path && ! -L $path ]]; then return 0; fi
    [[ -f $path && ! -L $path && $(stat -c '%u:%g:%a' "$path") == 0:0:644 ]] || return 1
    hash=$(sha256sum "$path")
    case ${hash%% *} in
        87c037de33a3e88565549f33dbc69410a38d3e2ed548d116d409e6397819a590 | 8c82488c7d0dbe41bbcb722e07c2e67f6ee76efc3308f3dbca8c642f7b9cca9e) ;;
        *)
            echo "Unrecognized legacy AWG unit" >&2
            return 1
            ;;
    esac
    state=$(systemctl is-active hestia-awg.service || :)
    case $state in
        active) legacy_awg_active=1 ;;
        inactive | failed) ;;
        *)
            echo "Cannot inspect legacy AWG runtime" >&2
            return 1
            ;;
    esac
}

# stop_legacy_awg waits for the previous service to retire its routes before any instance can use awg0.
stop_legacy_awg() {
    local binary=$1 id=$2
    if ((legacy_awg_active)); then
        systemctl stop hestia-awg.service || return 1
        if [[ -e /run/hestia-awg/routes.json || -L /run/hestia-awg/routes.json ]]; then
            [[ $id =~ ^[a-z][a-z0-9-]{0,62}$ ]] || return 1
            "$binary" -awg-retire-legacy "$id" 0 || return 1
        fi
    fi
    [[ ! -e /run/hestia-awg/ready && ! -e /run/hestia-awg/routes.json ]] || {
        echo "Legacy AWG route ownership was not retired" >&2
        return 1
    }
}

# wait_awg_proof waits for the kernel guards or the fresh ready signal from the restarted runtime.
wait_awg_proof() {
    local binary=$1 id=$2 slot=$3 proof=$4 until_time=$((SECONDS + ${5:-30})) marker=/run/hestia-awg/ready.$2
    while ((SECONDS < until_time)); do
        if [[ $proof == guards ]]; then
            if "$binary" -awg-guard "$id" "$slot"; then return 0; fi
        elif [[ -f $marker && ! -L $marker && $(stat -c '%u:%a' "$marker") == 0:600 && $(cat "$marker") == ready ]]; then
            return 0
        fi
        sleep 0.2
    done
    echo "AWG exit did not confirm $proof: $id" >&2
    return 1
}

# restart_ready_awg starts committed units under the installation lock. Manual peers await their backend behind proven guards.
restart_ready_awg() {
    local compiler=$1 binary=${2:-/usr/local/bin/hestia} plan id slot mode count unit marker
    plan=$(python3 -I "$compiler" --awg-start-plan /etc/hestia) || return 1
    while read -r id slot mode count; do
        [[ -n $id ]] || continue
        [[ $id =~ ^[a-z][a-z0-9-]{0,62}$ && $slot =~ ^([0-9]|[1-4][0-9])$ && ($mode == auto || $mode == manual) ]] || return 1
        unit=hestia-awg@${id}.service
        marker=/run/hestia-awg/ready.${id}
        systemctl stop "$unit" || return 1
        [[ ! -e $marker && ! -L $marker ]] || return 1
        systemctl start "$unit" || return 1
    done <<<"$plan"
    while read -r id slot mode count; do
        [[ -n $id ]] || continue
        if [[ $mode == manual ]]; then
            wait_awg_proof "$binary" "$id" "$slot" guards || return 1
        else
            wait_awg_proof "$binary" "$id" "$slot" ready || return 1
        fi
    done <<<"$plan"
}

# confirm_manual_awg checks bound egress for committed manual peers after sing-box has loaded their transport configuration.
confirm_manual_awg() {
    local compiler=$1 plan id slot mode count
    plan=$(python3 -I "$compiler" --awg-start-plan /etc/hestia) || return 1
    while read -r id slot mode count; do
        if [[ $mode == manual ]]; then
            [[ $id =~ ^[a-z][a-z0-9-]{0,62}$ ]] || return 1
            [[ $count =~ ^([1-9]|[1-5][0-9]|6[0-4])$ ]] || return 1
            wait_awg_proof /usr/local/bin/hestia "$id" "$slot" ready "$((30 + 12 * count))" || return 1
        fi
    done <<<"$plan"
}

# retire_migrated_awg releases the original singleton slot only after the new named instance is stopped.
retire_migrated_awg() {
    local binary=$1 id=$2
    if [[ -e /run/hestia-awg/routes.json.$id || -L /run/hestia-awg/routes.json.$id ]]; then
        "$binary" -awg-retire "$id" 0 || {
            echo "Cannot release AWG slot for the old service; dataplane remains stopped" >&2
            return 1
        }
    fi
}
