#!/bin/sh
# Toggle one allowlisted native Keenetic profile once and restore its original
# administrative and connection states. Run only after inventory, syntax, and
# management-route gates pass. Inputs: exact profile label, original admin
# state, and original connection state. Side effects: one temporary interface
# transition and an inverse restoration; status output contains no raw config.
set -eu

readonly NDMC=/bin/ndmc
readonly EXPECTED_NDMC_SHA256=6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e
readonly MAX_ADMIN_POLLS=10
readonly MAX_CONNECTION_POLLS=30
readonly WATCHDOG_SECONDS=90

label=${1-}
original_admin=${2-}
original_connection=${3-}

# profile_identity maps a user-approved display label to the exact ID and
# protocol established by the read-only inventory. Placeholders intentionally
# make the prototype refuse to run until those facts are confirmed.
profile_identity() {
    case "$label" in
        'Solar (Moscow)')
            profile_id=__UNVERIFIED_SOLAR_INTERFACE_ID__
            profile_type=__UNVERIFIED_SOLAR_PROTOCOL__
            ;;
        Poppuri)
            profile_id=__UNVERIFIED_POPPURI_INTERFACE_ID__
            profile_type=__UNVERIFIED_POPPURI_PROTOCOL__
            ;;
        *)
            return 1
            ;;
    esac
}

# control_interface requests only an allowlisted native interface up/down
# state. It suppresses device text, returning only the ndmc exit status.
control_interface() {
    requested_state=$1
    case "$requested_state" in
        up|down) ;;
        *) return 2 ;;
    esac
    "$NDMC" -c "interface $profile_id $requested_state" >/dev/null 2>&1
}

# read_status extracts exactly two normalized state values from a read-only
# show-interface response. Replace its fail-closed parser only after the
# device output format has been reviewed by the shared inventory sanitizer.
read_status() {
    raw_status=$("$NDMC" -c "show interface $profile_id" 2>/dev/null) || return 1
    parsed_status=$(printf '%s\n' "$raw_status" | awk '
        # TODO: map the verified KN-1012 output fields to admin=up|down and
        # connection=connected|disconnected|connecting|unknown. Emit nothing
        # else; reject missing, duplicate, or unrecognized fields.
        END { exit 42 }
    ') || return 1
    case "$parsed_status" in
        'admin=up connection=connected'|'admin=up connection=disconnected'|'admin=up connection=connecting'|'admin=up connection=unknown'|'admin=down connection=disconnected'|'admin=down connection=unknown')
            printf '%s\n' "$parsed_status"
            ;;
        *)
            return 1
            ;;
    esac
}

# wait_for_admin polls a normalized administrative state for at most the
# supplied number of one-second intervals; it never prints raw CLI output.
wait_for_admin() {
    target_admin=$1
    max_polls=$2
    poll_count=0
    while [ "$poll_count" -lt "$max_polls" ]; do
        current_status=$(read_status) || return 2
        case "$current_status" in
            "admin=$target_admin "*)
                printf 'admin_state=%s\n' "$target_admin"
                return 0
                ;;
        esac
        poll_count=$((poll_count + 1))
        sleep 1
    done
    printf 'admin_state=timeout target=%s\n' "$target_admin"
    return 1
}

# wait_for_connection polls a normalized connection state for a bounded time.
wait_for_connection() {
    target_connection=$1
    max_polls=$2
    poll_count=0
    while [ "$poll_count" -lt "$max_polls" ]; do
        current_status=$(read_status) || return 2
        case "$current_status" in
            *"connection=$target_connection")
                printf 'connection_state=%s\n' "$target_connection"
                return 0
                ;;
        esac
        poll_count=$((poll_count + 1))
        sleep 1
    done
    printf 'connection_state=timeout target=%s\n' "$target_connection"
    return 1
}

# restore_original requests the captured administrative state and verifies
# both administrative and connected/disconnected state within bounded waits.
restore_original() {
    restore_result=0
    if ! control_interface "$original_admin"; then
        printf 'restore_command=failed\n'
        return 1
    fi
    printf 'restore_command=accepted\n'
    if ! wait_for_admin "$original_admin" "$MAX_ADMIN_POLLS"; then
        restore_result=1
    fi
    if ! wait_for_connection "$original_connection" "$MAX_CONNECTION_POLLS"; then
        restore_result=1
    fi
    return "$restore_result"
}

# start_watchdog launches an independent bounded rollback before the first
# mutating command, so a lost SSH session still restores the original state.
start_watchdog() {
    (
        sleep "$WATCHDOG_SECONDS"
        restore_original
    ) >/dev/null 2>&1 &
    watchdog_pid=$!
}

# cleanup restores after any attempted transition, then cancels the watchdog;
# this trap runs on normal exit and catchable termination signals.
cleanup() {
    cleanup_rc=$?
    trap - EXIT HUP INT TERM
    if [ "$restore_needed" -eq 1 ]; then
        restore_original || cleanup_rc=1
    fi
    if [ -n "$watchdog_pid" ]; then
        kill "$watchdog_pid" >/dev/null 2>&1 || :
    fi
    exit "$cleanup_rc"
}

# Verify arguments, allowlisted identity, parser readiness, executable identity,
# and the inventory-captured state before starting the watchdog or mutation.
main() {
    [ "$#" -eq 3 ] || {
        printf 'result=refused reason=usage\n'
        return 2
    }
    case "$original_admin" in up|down) ;; *) printf 'result=refused reason=admin_state\n'; return 2 ;; esac
    case "$original_connection" in connected|disconnected) ;; *) printf 'result=refused reason=connection_state\n'; return 2 ;; esac
    profile_identity || {
        printf 'result=refused reason=profile_not_allowlisted\n'
        return 2
    }
    case "$profile_id:$profile_type" in
        *UNVERIFIED*) printf 'result=refused reason=inventory_not_bound\n'; return 2 ;;
    esac
    case "$profile_id" in *[!A-Za-z0-9_.:/-]*|'') printf 'result=refused reason=invalid_interface_id\n'; return 2 ;; esac
    [ -x "$NDMC" ] || { printf 'result=refused reason=ndmc_missing\n'; return 2; }
    actual_hash=$(sha256sum "$NDMC" 2>/dev/null | awk 'NR == 1 {print $1}') || return 2
    [ "$actual_hash" = "$EXPECTED_NDMC_SHA256" ] || {
        printf 'result=refused reason=ndmc_hash_mismatch\n'
        return 2
    }
    case "$profile_type" in
        *UNVERIFIED*) printf 'result=refused reason=protocol_not_confirmed\n'; return 2 ;;
    esac

    initial_status=$(read_status) || {
        printf 'result=refused reason=readback_unparsed\n'
        return 2
    }
    case "$initial_status" in
        "admin=$original_admin connection=$original_connection") ;;
        *) printf 'result=refused reason=inventory_state_mismatch\n'; return 2 ;;
    esac

    if [ "$original_admin" = up ]; then
        test_admin=down
        test_connection=disconnected
    else
        test_admin=up
        test_connection=connected
    fi
    restore_needed=0
    watchdog_pid=
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    start_watchdog

    # Mark restoration necessary before the command: even a nonzero ndmc exit
    # could follow a partially applied state change.
    restore_needed=1
    if ! control_interface "$test_admin"; then
        printf 'transition_command=failed target=%s\n' "$test_admin"
        return 1
    fi
    printf 'transition_command=accepted target=%s\n' "$test_admin"
    wait_for_admin "$test_admin" "$MAX_ADMIN_POLLS" || return 1
    if [ "$test_admin" = up ]; then
        wait_for_connection "$test_connection" "$MAX_CONNECTION_POLLS" || return 1
    else
        wait_for_connection "$test_connection" "$MAX_CONNECTION_POLLS" || return 1
    fi

    # Restore immediately and verify; clear the trap's rollback flag only after
    # both original state dimensions have been observed again.
    restore_original || return 1
    restore_needed=0
    printf 'result=completed label=%s type=%s admin_original=%s connection_original=%s\n' \
        "$label" "$profile_type" "$original_admin" "$original_connection"
}

restore_needed=0
watchdog_pid=
main "$@"
