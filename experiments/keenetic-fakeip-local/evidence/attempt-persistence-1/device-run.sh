# Test one own FakeIP mapping before and after a clean sing-box restart with a private cache file.
set -eu
umask 077
D=/opt/tmp/hestia-fakeip-local.persistence1
cd "$D"
box_pid=
helper_pid=
watchdog_pid=

# cleanup_owned stops only processes created by this attempt.
cleanup_owned() {
    if [ -n "$box_pid" ]; then
        kill -TERM "$box_pid" 2>/dev/null || true
        wait "$box_pid" 2>/dev/null || true
    fi
    if [ -n "$helper_pid" ]; then
        kill -TERM "$helper_pid" 2>/dev/null || true
        wait "$helper_pid" 2>/dev/null || true
    fi
    if [ -n "$watchdog_pid" ]; then
        kill -TERM "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
    fi
}
trap cleanup_owned EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# route_snapshot hashes all route/rule views without retaining their contents.
route_snapshot() {
    ip -4 route show table all | sha256sum
    ip -4 rule show | sha256sum
    ip -6 route show table all | sha256sum
    ip -6 rule show | sha256sum
}

# wait_started waits for the sing-box startup marker with a bounded deadline and exact process ID.
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

printf 'run_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'routes_rules_before\n'
before=$(route_snapshot)
printf '%s\n' "$before"
./hestia-fakeip-harness serve >harness.log 2>&1 &
helper_pid=$!
printf '%s\n' "$helper_pid" >owned-pids
(
    sleep 100
    if [ ! -e complete ]; then
        while read -r process_id; do
            kill -TERM "$process_id" 2>/dev/null || true
        done <owned-pids
    fi
) </dev/null >/dev/null 2>&1 &
watchdog_pid=$!
attempt=0
while ! grep -q ' ready dns=' harness.log; do
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
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c ./singbox-fakeip-cache.json >sing-box-1.log 2>&1 &
box_pid=$!
printf '%s\n' "$helper_pid" "$box_pid" >owned-pids
wait_started sing-box-1.log "$box_pid"
./hestia-fakeip-harness probe >probe-1.log 2>&1
kill -TERM "$box_pid"
set +e
wait "$box_pid"
first_stop_rc=$?
set -e
box_pid=
printf 'first_singbox_stop_wait_exit=%s\n' "$first_stop_rc"
test -s fakeip-cache.db
/opt/bin/sha256sum fakeip-cache.db
wc -c fakeip-cache.db
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c ./singbox-fakeip-cache.json >sing-box-2.log 2>&1 &
box_pid=$!
printf '%s\n' "$helper_pid" "$box_pid" >owned-pids
wait_started sing-box-2.log "$box_pid"
./hestia-fakeip-harness resume >probe-2.log 2>&1
kill -TERM "$box_pid"
set +e
wait "$box_pid"
second_stop_rc=$?
set -e
box_pid=
printf 'second_singbox_stop_wait_exit=%s\n' "$second_stop_rc"
kill -TERM "$helper_pid"
set +e
wait "$helper_pid"
helper_stop_rc=$?
set -e
helper_pid=
printf 'helper_stop_wait_exit=%s\n' "$helper_stop_rc"
test -s fakeip.txt
test -s fakeip-cache.db
printf 'fakeip='; cat fakeip.txt
printf 'probe_first_and_resume\n'
cat probe-1.log probe-2.log
printf 'cache_file_metadata_final\n'
/opt/bin/sha256sum fakeip-cache.db
wc -c fakeip-cache.db
printf 'routes_rules_after\n'
after=$(route_snapshot)
printf '%s\n' "$after"
if [ "$before" != "$after" ]; then
    printf 'route_rule_hashes_equal=false\n'
    exit 1
fi
touch complete
printf 'route_rule_hashes_equal=true\nrun_end_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
grep -E 'fakeip-local\.test|127\.0\.0\.1:1935[234]|service\.fakeip-local\.test' sing-box-1.log sing-box-2.log || true
cat harness.log
