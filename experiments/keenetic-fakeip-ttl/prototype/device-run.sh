#!/bin/sh
# Run one bounded TTL-expiry FakeIP reuse study with only owned loopback processes.
set -eu
umask 077
D=/opt/tmp/hestia-r4-ttl-attempt2
cd "$D"
box_pid=
helper_pid=
watchdog_pid=

# cleanup_owned stops only the exact helper and sing-box PIDs created by this runner.
cleanup_owned() {
    : >abort
    for process_id in "$box_pid" "$helper_pid" "$watchdog_pid"; do
        if [ -n "$process_id" ]; then
            kill -TERM "$process_id" 2>/dev/null || true
        fi
    done
    for process_id in "$box_pid" "$helper_pid" "$watchdog_pid"; do
        if [ -n "$process_id" ]; then
            wait "$process_id" 2>/dev/null || true
        fi
    done
}
trap cleanup_owned EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# route_snapshot hashes the four route/rule views without saving topology contents.
route_snapshot() {
    ip -4 route show table all | sha256sum
    ip -4 rule show | sha256sum
    ip -6 route show table all | sha256sum
    ip -6 rule show | sha256sum
}

# wait_started requires the exact sing-box process to emit its startup marker before timeout.
wait_started() {
    log_file=$1
    process_id=$2
    attempt=0
    while ! grep -q 'sing-box started' "$log_file"; do
        if ! kill -0 "$process_id" 2>/dev/null; then
            cat "$log_file"
            return 1
        fi
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 15 ]; then
            cat "$log_file"
            return 1
        fi
        sleep 1
    done
}

printf 'run_start_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'routes_rules_before\n'
before=$(route_snapshot)
printf '%s\n' "$before"
printf 'firmware_release='
cat /etc/version 2>/dev/null || true
uname -a
./fakeip-ttl-harness serve >harness.log 2>&1 &
helper_pid=$!
printf '%s\n' "$helper_pid" >helper-pid
printf 'helper_pid=%s\n' "$helper_pid"
(
    seconds=0
    while [ "$seconds" -lt 75 ] && [ ! -e complete ] && [ ! -e abort ]; do
        sleep 1
        seconds=$((seconds + 1))
    done
    if [ ! -e complete ] && [ ! -e abort ]; then
        kill -TERM "$(cat helper-pid)" 2>/dev/null || true
        if [ -s box-pid ]; then kill -TERM "$(cat box-pid)" 2>/dev/null || true; fi
    fi
) </dev/null >/dev/null 2>&1 &
watchdog_pid=$!
attempt=0
while ! grep -q 'ready dns=' harness.log; do
    if ! kill -0 "$helper_pid" 2>/dev/null; then
        cat harness.log
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 10 ]; then
        cat harness.log
        exit 1
    fi
    sleep 1
done
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box version >sing-box-version.txt 2>&1
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box check -c ./singbox-fakeip-ttl.json >sing-box-check.txt 2>&1
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c ./singbox-fakeip-ttl.json >sing-box.log 2>&1 &
box_pid=$!
printf '%s\n' "$box_pid" >box-pid
printf 'singbox_pid=%s\n' "$box_pid"
wait_started sing-box.log "$box_pid"
printf 'first_probe_start_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
./fakeip-ttl-harness probe >probe-before-expiry.log 2>&1
printf 'first_probe_end_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'saved_fakeip='
cat fakeip.txt
sleep 5
printf 'phase_switch_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'B\n' >phase.txt
./fakeip-ttl-harness direct >direct-controls-after-switch.log 2>&1
printf 'reuse_probe_start_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
./fakeip-ttl-harness resume >probe-after-expiry.log 2>&1
printf 'reuse_probe_end_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'saved_fakeip_after='
cat fakeip.txt
printf 'upstream_query_count='
grep -c 'synthetic DNS A answer=' harness.log || true
printf 'probes_and_controls\n'
cat probe-before-expiry.log direct-controls-after-switch.log probe-after-expiry.log
printf 'singbox_fakeip_and_domain_events\n'
grep -E 'fakeip|fakeip-ttl\.test|127\.0\.0\.[12]:1931[34]' sing-box.log || true
printf 'target_dns_and_marker_events\n'
cat harness.log
printf 'routes_rules_after\n'
after=$(route_snapshot)
printf '%s\n' "$after"
if [ "$before" != "$after" ]; then
    printf 'route_rule_hashes_equal=false\n'
    exit 1
fi
touch complete
printf 'route_rule_hashes_equal=true\nrun_end_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
