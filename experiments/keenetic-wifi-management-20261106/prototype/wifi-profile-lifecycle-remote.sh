#!/bin/sh
# Disable and restore only the already-connected KN-1012 5GHz WISP station.
# Inputs are fixed in this file; all raw CLI output is filtered in memory/FIFO.
set -eu
umask 077

readonly NDMC=/bin/ndmc
readonly EXPECTED_NDMC_SHA256=6e6b0bee69e1270160a16711b6a64f4e036b9b984d8eb80acdf76403c243121e
readonly STATION_ID=WifiMaster1/WifiStation0
readonly STATION_TYPE=wifistation
readonly EXPECTED_DESCRIPTION=iPhone
readonly EXPECTED_SSID='White paper'
readonly EXPECTED_PRIORITY=65531
readonly WAN_ID=GigabitEthernet1
readonly WAN_TYPE=gigabitethernet
readonly WAN_PRIORITY=65532
readonly STATUS_TIMEOUT_SECONDS=3
readonly CONTROL_TIMEOUT_SECONDS=5
readonly ADMIN_POLLS=8
readonly CONNECTION_POLLS=20
readonly WATCHDOG_SECONDS=90

read_sequence=0
restore_needed=0
watchdog_pid=
work_dir="/tmp/hestia-wifi-lifecycle-$$"

# stop_timer cancels only the timeout helper created for one command PID.
stop_timer() {
    timer_pid=$1
    kill "$timer_pid" >/dev/null 2>&1 || :
    wait "$timer_pid" >/dev/null 2>&1 || :
}

# start_kill_timer bounds one owned ndmc child and suppresses helper output.
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

# run_control issues only the exact station up/no-up command and hides CLI text.
run_control() {
    requested_state=$1
    case "$requested_state" in
        up) control_command="interface $STATION_ID up" ;;
        down) control_command="interface $STATION_ID no up" ;;
        *) return 2 ;;
    esac
    "$NDMC" -c "$control_command" >/dev/null 2>&1 &
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

# parse_status extracts only identity booleans, admin/link state and route priority.
parse_status() {
    expected_id=$1
    expected_type=$2
    expected_priority=$3
    awk -F: -v wanted_id="$expected_id" -v wanted_type="$expected_type" -v wanted_priority="$expected_priority" \
        -v wanted_description="$EXPECTED_DESCRIPTION" -v wanted_ssid="$EXPECTED_SSID" '
        function trim(value) {
            sub(/^[ \t\r]+/, "", value)
            sub(/[ \t\r]+$/, "", value)
            return value
        }
        function normalize_bool(value) {
            value = tolower(value)
            if (value == "true" || value == "yes" || value == "connected") return "yes"
            if (value == "false" || value == "no" || value == "disconnected") return "no"
            return value
        }
        function add(key, value) {
            if (seen[key] && values[key] != value) invalid = 1
            values[key] = value
            seen[key] = 1
        }
        {
            line = $0
            indent = match(line, /[^ \t]/) - 1
            separator = index(line, ":")
            if (!separator) next
            key = tolower(trim(substr(line, 1, separator - 1)))
            value = trim(substr(line, separator + 1))
            if (key == "id" && indent == 15) {
                if (active) { finished = 1; exit }
                if (value == wanted_id) { active = 1; ids++; add("id", value) }
                next
            }
            if (!active || finished) next
            if (key == "type" && indent == 13) add("type", tolower(value))
            else if (key == "description" && indent == 6) add("description_match", value == wanted_description ? "yes" : "no")
            else if (key == "ssid" && indent == 13) add("ssid_match", value == wanted_ssid ? "yes" : "no")
            else if (key == "state" && indent == 12) add("admin", tolower(value))
            else if (key == "link" && indent == 13) add("link", tolower(value))
            else if (key == "connected" && indent == 8) add("connected", normalize_bool(value))
            else if (key == "defaultgw" && indent == 8) add("defaultgw", normalize_bool(value))
            else if (key == "priority" && indent == 9) add("priority", value)
        }
        END {
            if (ids != 1 || invalid || values["id"] != wanted_id || values["type"] != wanted_type ||
                values["admin"] !~ /^(up|down)$/ || values["link"] !~ /^(up|down|running|stopped)$/ ||
                values["connected"] !~ /^(yes|no)$/ || values["defaultgw"] !~ /^(yes|no)$/ ||
                values["priority"] != wanted_priority) exit 42
            if (wanted_type == "wifistation" && (!seen["description_match"] || !seen["ssid_match"] ||
                values["description_match"] != "yes" || values["ssid_match"] != "yes")) exit 43
            printf "admin=%s link=%s connected=%s defaultgw=%s priority=%s", values["admin"], values["link"],
                values["connected"], values["defaultgw"], values["priority"]
            if (wanted_type == "wifistation") printf " description_match=%s ssid_match=%s", values["description_match"], values["ssid_match"]
            printf "\n"
        }
    '
}

# read_status uses a FIFO so raw CLI output is never written to a regular file.
read_status() {
    target_id=$1
    target_type=$2
    target_priority=$3
    read_sequence=$((read_sequence + 1))
    fifo_path="$work_dir/status-$read_sequence.fifo"
    safe_path="$work_dir/status-$read_sequence.safe"
    mkfifo "$fifo_path" || return 1
    parse_status "$target_id" "$target_type" "$target_priority" <"$fifo_path" >"$safe_path" &
    parser_pid=$!
    "$NDMC" -c "show interface $target_id" >"$fifo_path" 2>/dev/null &
    query_pid=$!
    timer_pid=$(start_kill_timer "$query_pid" "$STATUS_TIMEOUT_SECONDS")
    if wait "$query_pid"; then query_rc=0; else query_rc=$?; fi
    stop_timer "$timer_pid"
    if wait "$parser_pid"; then parser_rc=0; else parser_rc=$?; fi
    status_value=
    [ ! -f "$safe_path" ] || status_value=$(cat "$safe_path")
    rm -f "$fifo_path" "$safe_path"
    [ "$query_rc" -eq 0 ] && [ "$parser_rc" -eq 0 ] || return 1
    printf '%s\n' "$status_value"
}

# check_wan requires the preflighted wired WAN to stay connected and default.
check_wan() {
    wan_status=$(read_status "$WAN_ID" "$WAN_TYPE" "$WAN_PRIORITY") || return 1
    case "$wan_status" in
        'admin=up link=up connected=yes defaultgw=yes priority=65532')
            printf 'wan_status=%s\n' "$wan_status"
            return 0
            ;;
        *)
            printf 'wan_status=unexpected\n'
            return 1
            ;;
    esac
}

# wait_station_state polls admin and connected independently with a fixed bound.
wait_station_state() {
    desired_admin=$1
    desired_connected=$2
    poll_count=$3
    attempt=0
    while [ "$attempt" -lt "$poll_count" ]; do
        station_status=$(read_status "$STATION_ID" "$STATION_TYPE" "$EXPECTED_PRIORITY") || return 2
        case "$station_status" in
            "admin=$desired_admin "*)
                case "$station_status" in
                    *"connected=$desired_connected "*)
                        printf 'station_status=%s\n' "$station_status"
                        return 0
                        ;;
                esac
                ;;
        esac
        attempt=$((attempt + 1))
        sleep 1
    done
    printf 'station_status=timeout admin=%s connected=%s\n' "$desired_admin" "$desired_connected"
    return 1
}

# restore_station re-enables the originally-up station and verifies association.
restore_station() {
    if ! run_control up; then
        printf 'restore_command=failed\n'
        return 1
    fi
    printf 'restore_command=accepted\n'
    wait_station_state up yes "$CONNECTION_POLLS" || return 1
    check_wan || return 1
    return 0
}

# watchdog_restore re-enables the station if the SSH-driven main process disappears.
watchdog_restore() {
    trap '' HUP
    sleep "$WATCHDOG_SECONDS"
    [ -f "$work_dir/complete" ] && exit 0
    run_control up >/dev/null 2>&1 || :
    sleep 2
    rm -f "$work_dir/active"
    rm -rf "$work_dir"
}

# cleanup restores the original up state on normal exit and catchable signals.
cleanup() {
    cleanup_rc=$?
    trap - EXIT HUP INT TERM
    if [ "$restore_needed" -eq 1 ]; then
        if restore_station; then
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

# main validates exact initial identity/route, disables once, reads down/no, then restores.
main() {
    actual_hash=$(sha256sum "$NDMC" 2>/dev/null | awk 'NR == 1 {print $1}') || return 2
    [ "$actual_hash" = "$EXPECTED_NDMC_SHA256" ] || {
        printf 'result=refused reason=ndmc_hash_mismatch\n'
        return 2
    }
    station_initial=$(read_status "$STATION_ID" "$STATION_TYPE" "$EXPECTED_PRIORITY") || {
        printf 'result=refused reason=station_preflight_unparsed\n'
        return 2
    }
    case "$station_initial" in
        'admin=up link=up connected=yes defaultgw=no priority=65531 description_match=yes ssid_match=yes') ;;
        *)
            printf 'result=refused reason=station_preflight_mismatch\n'
            return 2
            ;;
    esac
    printf 'preflight_station=%s\n' "$station_initial"
    check_wan || {
        printf 'result=refused reason=wan_preflight_mismatch\n'
        return 2
    }

    watchdog_restore >/dev/null 2>&1 &
    watchdog_pid=$!
    restore_needed=1
    if ! run_control down; then
        printf 'transition=failed target=down\n'
        return 1
    fi
    printf 'transition=accepted target=down\n'
    wait_station_state down no "$ADMIN_POLLS" || return 1
    check_wan || return 1

    if ! run_control up; then
        printf 'transition=failed target=up\n'
        return 1
    fi
    printf 'transition=accepted target=up\n'
    wait_station_state up yes "$CONNECTION_POLLS" || return 1
    check_wan || return 1
    restore_needed=0
    printf 'result=completed station_restored=up connected=yes default_route=GigabitEthernet1\n'
}

mkdir "$work_dir" || {
    printf 'result=refused reason=temporary_workspace_unavailable\n'
    exit 2
}
: >"$work_dir/active"
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
main "$@"
