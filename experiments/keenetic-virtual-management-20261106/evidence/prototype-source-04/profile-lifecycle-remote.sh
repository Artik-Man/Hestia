#!/bin/sh
# Toggle one approved native Keenetic VPN profile once and restore its captured
# state. Inputs: exact display label, initial admin state, and connected flag.
# Side effects: temporary native up/down state; no profile edit or config save.
set -eu
umask 077

readonly NDMC=/bin/ndmc
readonly EXPECTED_NDMC_SHA256=6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e
readonly ADMIN_POLLS=8
readonly CONNECTION_POLLS=15
readonly STATUS_TIMEOUT_SECONDS=2
readonly CONTROL_TIMEOUT_SECONDS=5
readonly WATCHDOG_SECONDS=240
readonly PROFILE_LABEL_SOLAR='Solar (Moscow)'
readonly PROFILE_ID_SOLAR=Wireguard2
readonly PROFILE_TYPE_SOLAR=wireguard
readonly PROFILE_LABEL_POPPURI=Poppuri
readonly PROFILE_ID_POPPURI=SSTP1
readonly PROFILE_TYPE_POPPURI=sstp

label=${1-}
original_admin=${2-}
original_connected=${3-}

# profile_identity binds an approved display label to the inventory-confirmed
# native interface ID and protocol. It refuses every other profile.
profile_identity() {
    case "$label" in
        "$PROFILE_LABEL_SOLAR")
            profile_id=$PROFILE_ID_SOLAR
            profile_type=$PROFILE_TYPE_SOLAR
            ;;
        "$PROFILE_LABEL_POPPURI")
            profile_id=$PROFILE_ID_POPPURI
            profile_type=$PROFILE_TYPE_POPPURI
            ;;
        *)
            return 1
            ;;
    esac
}

# stop_timer cancels only the timeout helper started for one owned ndmc child.
stop_timer() {
    timer_pid=$1
    kill "$timer_pid" >/dev/null 2>&1 || :
    wait "$timer_pid" >/dev/null 2>&1 || :
}

# start_kill_timer starts a bounded helper that terminates only the ndmc PID
# supplied by this invocation if that command exceeds its timeout.
start_kill_timer() {
    command_pid=$1
    timeout_seconds=$2
    (
        trap '' HUP
        sleep "$timeout_seconds"
        kill -TERM "$command_pid" >/dev/null 2>&1 || exit 0
        sleep 1
        kill -KILL "$command_pid" >/dev/null 2>&1 || :
    ) >/dev/null 2>&1 &
    printf '%s\n' "$!"
}

# control_interface invokes only the documented up/down action on the bound
# profile, suppresses CLI text, and returns failure for timeout or command error.
control_interface() {
    requested_state=$1
    case "$requested_state" in up|down) ;; *) return 2 ;; esac
    "$NDMC" -c "interface $profile_id $requested_state" >/dev/null 2>&1 &
    command_pid=$!
    timer_pid=$(start_kill_timer "$command_pid" "$CONTROL_TIMEOUT_SECONDS")
    if wait "$command_pid"; then
        command_rc=0
    else
        command_rc=$?
    fi
    stop_timer "$timer_pid"
    return "$command_rc"
}

# parse_one_profile reads a targeted show-interface stream and emits only
# admin/link/status/connected enums from its unique top-level interface record.
parse_one_profile() {
    awk -F: -v wanted_id="$profile_id" -v wanted_label="$label" -v wanted_type="$profile_type" '
        function trim(value) {
            sub(/^[ \t\r]+/, "", value)
            sub(/[ \t\r]+$/, "", value)
            return value
        }
        function record_value(key, value) {
            if (seen[key] && fields[key] != value) {
                invalid = 1
            } else {
                fields[key] = value
                seen[key] = 1
            }
        }
        {
            line = $0
            indent = match(line, /[^ \t]/) - 1
            separator = index(line, ":")
            if (!separator) {
                next
            }
            key = tolower(trim(substr(line, 1, separator - 1)))
            value = trim(substr(line, separator + 1))
            if (key == "id" && indent == 15) {
                if (active) {
                    finished = 1
                    exit
                }
                if (value == wanted_id) {
                    active = 1
                    id_count++
                    record_value("id", value)
                }
                next
            }
            if (!active || finished) {
                next
            }
            if (key == "description" && indent == 6) {
                record_value("description", value)
            } else if (key == "type" && indent == 13) {
                record_value("type", tolower(value))
            } else if (key == "state" && indent == 12) {
                record_value("admin", tolower(value))
            } else if (key == "link" && indent == 13) {
                record_value("link", tolower(value))
            } else if (key == "status" && indent == 15) {
                record_value("status", tolower(value))
            } else if (key == "connected" && indent == 8) {
                value = tolower(value)
                if (value == "true" || value == "yes" || value == "connected") {
                    value = "yes"
                } else if (value == "false" || value == "no" || value == "disconnected") {
                    value = "no"
                }
                record_value("connected", value)
            }
        }
        END {
            if (id_count != 1 || invalid || fields["id"] != wanted_id ||
                fields["description"] != wanted_label || fields["type"] != wanted_type ||
                (fields["admin"] != "up" && fields["admin"] != "down") ||
                (fields["link"] != "up" && fields["link"] != "down" && fields["link"] != "running" && fields["link"] != "stopped") ||
                (fields["connected"] != "yes" && fields["connected"] != "no")) {
                exit 42
            }
            status = seen["status"] ? fields["status"] : "none"
            if (status !~ /^(up|down|connected|disconnected|connecting|active|inactive|none)$/) {
                exit 43
            }
            printf "admin=%s link=%s connected=%s status=%s\n", fields["admin"], fields["link"], fields["connected"], status
        }
    '
}

# read_status streams the command directly into the allowlist parser through a
# FIFO, bounding ndmc and avoiding any raw-output file or journal.
read_status() {
    read_sequence=$((read_sequence + 1))
    fifo_path="$work_dir/status-$read_sequence.fifo"
    safe_path="$work_dir/status-$read_sequence.safe"
    mkfifo "$fifo_path" || return 1
    parse_one_profile <"$fifo_path" >"$safe_path" &
    parser_pid=$!
    "$NDMC" -c "show interface $profile_id" >"$fifo_path" 2>/dev/null &
    query_pid=$!
    timer_pid=$(start_kill_timer "$query_pid" "$STATUS_TIMEOUT_SECONDS")
    if wait "$query_pid"; then
        query_rc=0
    else
        query_rc=$?
    fi
    stop_timer "$timer_pid"
    if wait "$parser_pid"; then
        parser_rc=0
    else
        parser_rc=$?
    fi
    status_value=
    if [ -f "$safe_path" ]; then
        status_value=$(cat "$safe_path")
    fi
    rm -f "$fifo_path" "$safe_path"
    [ "$query_rc" -eq 0 ] && [ "$parser_rc" -eq 0 ] || return 1
    printf '%s\n' "$status_value"
}

# wait_for_admin polls only the administrative state for a bounded number of
# read_status calls and reports the device's accepted state separately.
wait_for_admin() {
    target_admin=$1
    attempt=0
    while [ "$attempt" -lt "$ADMIN_POLLS" ]; do
        current_status=$(read_status) || return 2
        case "$current_status" in
            "admin=$target_admin "*)
                printf 'admin_state=%s\n' "$target_admin"
                return 0
                ;;
        esac
        attempt=$((attempt + 1))
        sleep 1
    done
    printf 'admin_state=timeout target=%s\n' "$target_admin"
    return 1
}

# wait_for_connected polls the Keenetic-reported connected flag separately
# from admin/link/status; it does not claim a peer handshake or data transfer.
wait_for_connected() {
    target_connected=$1
    attempt=0
    while [ "$attempt" -lt "$CONNECTION_POLLS" ]; do
        current_status=$(read_status) || return 2
        case "$current_status" in
            *"connected=$target_connected "*)
                printf 'connection_state=%s\n' "$target_connected"
                printf 'link_status=%s\n' "${current_status#*link=}"
                return 0
                ;;
        esac
        attempt=$((attempt + 1))
        sleep 1
    done
    printf 'connection_state=timeout target=%s\n' "$target_connected"
    return 1
}

# restore_original resets the profile to the initial admin state and waits for
# the original device-reported connected flag within bounded poll counts.
restore_original() {
    restore_result=0
    if ! control_interface "$original_admin"; then
        printf 'restore_command=failed\n'
        return 1
    fi
    printf 'restore_command=accepted\n'
    wait_for_admin "$original_admin" || restore_result=1
    wait_for_connected "$original_connected" || restore_result=1
    return "$restore_result"
}

# watchdog_restore survives SSH hangup, waits a bounded interval, then restores
# the captured state if the main session did not mark completion.
watchdog_restore() {
    trap '' HUP
    sleep "$WATCHDOG_SECONDS"
    [ -f "$work_dir/complete" ] && exit 0
    restore_original >/dev/null 2>&1 || :
    rm -f "$work_dir/active"
    rm -rf "$work_dir"
}

# cleanup restores any attempted state change on normal exit or catchable
# signal. If restoration fails, it leaves the watchdog armed for a retry.
cleanup() {
    cleanup_rc=$?
    trap - EXIT HUP INT TERM
    if [ "$restore_needed" -eq 1 ]; then
        if restore_original; then
            restore_needed=0
        else
            cleanup_rc=1
            printf 'restore_status=failed watchdog_remains_armed=yes\n'
        fi
    fi
    if [ "$restore_needed" -eq 0 ]; then
        : >"$work_dir/complete"
        if [ -n "$watchdog_pid" ]; then
            kill "$watchdog_pid" >/dev/null 2>&1 || :
            wait "$watchdog_pid" >/dev/null 2>&1 || :
        fi
        rm -rf "$work_dir"
    fi
    exit "$cleanup_rc"
}

# main validates the pinned runtime and inventory-captured state, then performs
# exactly one up transition and restores the original down state.
main() {
    [ "$#" -eq 3 ] || { printf 'result=refused reason=usage\n'; return 2; }
    profile_identity || { printf 'result=refused reason=profile_not_allowlisted\n'; return 2; }
    [ "$original_admin" = down ] || { printf 'result=refused reason=original_admin_must_be_down\n'; return 2; }
    [ "$original_connected" = no ] || { printf 'result=refused reason=original_connected_must_be_no\n'; return 2; }
    case "$profile_id" in *[!A-Za-z0-9_.:/-]*|'') printf 'result=refused reason=invalid_interface_id\n'; return 2 ;; esac
    [ -x "$NDMC" ] || { printf 'result=refused reason=ndmc_missing\n'; return 2; }
    actual_hash=$(sha256sum "$NDMC" 2>/dev/null | awk 'NR == 1 {print $1}') || return 2
    [ "$actual_hash" = "$EXPECTED_NDMC_SHA256" ] || {
        printf 'result=refused reason=ndmc_hash_mismatch\n'
        return 2
    }

    initial_status=$(read_status) || {
        printf 'result=refused reason=readback_unparsed\n'
        return 2
    }
    case "$initial_status" in
        "admin=$original_admin "*) ;;
        *) printf 'result=refused reason=inventory_state_mismatch\n'; return 2 ;;
    esac
    case "$initial_status" in
        *"connected=$original_connected "*) ;;
        *) printf 'result=refused reason=inventory_connection_mismatch\n'; return 2 ;;
    esac

    restore_needed=0
    watchdog_pid=
    watchdog_restore >/dev/null 2>&1 &
    watchdog_pid=$!
    restore_needed=1
    if ! control_interface up; then
        printf 'transition_command=failed target=up\n'
        return 1
    fi
    printf 'transition_command=accepted target=up\n'
    wait_for_admin up || return 1
    wait_for_connected yes || return 1

    if ! restore_original; then
        printf 'restore_status=failed watchdog_remains_armed=yes\n'
        return 1
    fi
    restore_needed=0
    printf 'result=completed label=%s id=%s type=%s initial_admin=%s initial_connected=%s\n' \
        "$label" "$profile_id" "$profile_type" "$original_admin" "$original_connected"
}

read_sequence=0
restore_needed=0
watchdog_pid=
profile_identity || { printf 'result=refused reason=profile_not_allowlisted\n'; exit 2; }
work_dir="/tmp/hestia-vpn-lifecycle-$profile_id-$$"
mkdir "$work_dir" || { printf 'result=refused reason=tempdir_unavailable\n'; exit 2; }
: >"$work_dir/active"
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
main "$@"
