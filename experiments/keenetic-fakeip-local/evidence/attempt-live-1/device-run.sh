# Run only the own loopback FakeIP probe with exact-PID cleanup and a 100-second watchdog.
set -eu
umask 077
D=/opt/tmp/hestia-fakeip-local.20261106-1920
cd "$D"
box_pid=
helper_pid=
watchdog_pid=

# cleanup_owned stops only the processes created by this exact attempt.
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

# route_hashes prints hashes only, never route/rule contents or topology.
route_hashes() {
    ip -4 route show table all | sha256sum
    ip -4 rule show | sha256sum
    ip -6 route show table all | sha256sum
    ip -6 rule show | sha256sum
}

# wait_ready waits for the startup log marker while checking the owned PID and a fixed deadline.
wait_ready() {
    log_file=$1
    process_id=$2
    attempt=0
    while ! grep -q 'sing-box started' "$log_file"; do
        if ! kill -0 "$process_id" 2>/dev/null; then
            return 1
        fi
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 15 ]; then
            return 1
        fi
        sleep 1
    done
}

printf 'run_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'routes_rules_before\n'
route_hashes
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
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q '^ready ' harness.log; then
        break
    fi
    if ! kill -0 "$helper_pid" 2>/dev/null; then
        cat harness.log
        exit 1
    fi
    sleep 1
done
grep -q '^ready ' harness.log
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c ./singbox-fakeip.json >sing-box-1.log 2>&1 &
box_pid=$!
printf '%s\n' "$helper_pid" "$box_pid" >owned-pids
wait_ready sing-box-1.log "$box_pid"
./hestia-fakeip-harness probe >probe-1.log 2>&1
kill -TERM "$box_pid"
set +e
wait "$box_pid"
box_wait_rc=$?
set -e
box_pid=
printf 'first_singbox_stop_wait_exit=%s\n' "$box_wait_rc"
test -s fakeip-cache.db
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c ./singbox-fakeip.json >sing-box-2.log 2>&1 &
box_pid=$!
printf '%s\n' "$helper_pid" "$box_pid" >owned-pids
wait_ready sing-box-2.log "$box_pid"
./hestia-fakeip-harness resume >probe-2.log 2>&1
kill -TERM "$box_pid"
set +e
wait "$box_pid"
box_wait_rc=$?
set -e
box_pid=
printf 'second_singbox_stop_wait_exit=%s\n' "$box_wait_rc"
kill -TERM "$helper_pid"
set +e
wait "$helper_pid"
helper_wait_rc=$?
set -e
helper_pid=
printf 'helper_stop_wait_exit=%s\n' "$helper_wait_rc"
test -s fakeip.txt
test -s fakeip-cache.db
printf 'fakeip='; cat fakeip.txt
printf 'routes_rules_after\n'
route_hashes
touch complete
printf 'run_complete=true\nrun_end_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
cat probe-1.log probe-2.log harness.log
grep -E 'fakeip-local\.test|127\.0\.0\.1:1935[234]|service\.fakeip-local\.test' sing-box-1.log sing-box-2.log || true
