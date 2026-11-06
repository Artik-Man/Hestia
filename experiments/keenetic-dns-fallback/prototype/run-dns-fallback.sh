#!/bin/sh
# Run one bounded synthetic DNS test and clean up only its own processes and directory on timeout.
set -eu
umask 077
work=/opt/tmp/hestia-r4-dns-20261106-2239-f0b3
cd "$work"

route4_before=$(ip -4 route show table all | sha256sum | awk '{print $1}')
rules4_before=$(ip -4 rule show | sha256sum | awk '{print $1}')
route6_before=$(ip -6 route show table all | sha256sum | awk '{print $1}')
rules6_before=$(ip -6 rule show | sha256sum | awk '{print $1}')
printf 'started_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >run-status.txt
sha256sum dns-fallback-helper sing-box singbox-dns.json >input-sha256.txt

./dns-fallback-helper responder >responder.log 2>&1 &
helper_pid=$!
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c singbox-dns.json >sing-box.log 2>&1 &
singbox_pid=$!
(
    watchdog_sleep_pid=
    trap '[ -z "$watchdog_sleep_pid" ] || kill "$watchdog_sleep_pid" 2>/dev/null || true' EXIT
    trap 'exit 0' HUP INT TERM
    sleep 90 &
    watchdog_sleep_pid=$!
    wait "$watchdog_sleep_pid"
    kill -TERM "$singbox_pid" "$helper_pid" 2>/dev/null || true
    sleep 2
    kill -KILL "$singbox_pid" "$helper_pid" 2>/dev/null || true
    rm -rf "$work"
) </dev/null >/dev/null 2>&1 &
watchdog_pid=$!
printf 'helper_pid=%s\nsingbox_pid=%s\nwatchdog_pid=%s\nwatchdog_seconds=90\n' "$helper_pid" "$singbox_pid" "$watchdog_pid" >>run-status.txt

attempt=0
while ! grep -q 'responder ready' responder.log || ! grep -q 'sing-box started' sing-box.log; do
    if ! kill -0 "$helper_pid" 2>/dev/null || ! kill -0 "$singbox_pid" 2>/dev/null; then
        printf 'startup=failed\n' >>run-status.txt
        break
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 20 ]; then
        printf 'startup=timeout\n' >>run-status.txt
        break
    fi
    sleep 1
done

probe_rc=1
if grep -q 'responder ready' responder.log && grep -q 'sing-box started' sing-box.log; then
    printf 'startup=ready\n' >>run-status.txt
    if ./dns-fallback-helper probe >probe.log 2>&1; then
        probe_rc=0
    else
        probe_rc=$?
    fi
    printf 'probe_exit=%s\n' "$probe_rc" >>run-status.txt
fi

kill -TERM "$singbox_pid" "$helper_pid" 2>/dev/null || true
wait "$singbox_pid" 2>/dev/null || true
wait "$helper_pid" 2>/dev/null || true
kill "$watchdog_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
if kill -0 "$singbox_pid" 2>/dev/null || kill -0 "$helper_pid" 2>/dev/null; then
    printf 'owned_process_cleanup=failed\n' >>run-status.txt
    probe_rc=1
else
    printf 'owned_process_cleanup=confirmed\n' >>run-status.txt
fi

route4_after=$(ip -4 route show table all | sha256sum | awk '{print $1}')
rules4_after=$(ip -4 rule show | sha256sum | awk '{print $1}')
route6_after=$(ip -6 route show table all | sha256sum | awk '{print $1}')
rules6_after=$(ip -6 rule show | sha256sum | awk '{print $1}')
printf 'routes4_before=%s\nroutes4_after=%s\nrules4_before=%s\nrules4_after=%s\nroutes6_before=%s\nroutes6_after=%s\nrules6_before=%s\nrules6_after=%s\n' \
    "$route4_before" "$route4_after" "$rules4_before" "$rules4_after" \
    "$route6_before" "$route6_after" "$rules6_before" "$rules6_after" >route-rule-hashes.txt
[ "$route4_before" = "$route4_after" ] && [ "$rules4_before" = "$rules4_after" ] &&
    [ "$route6_before" = "$route6_after" ] && [ "$rules6_before" = "$rules6_after" ] || probe_rc=1
printf 'finished_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >>run-status.txt
cat run-status.txt route-rule-hashes.txt
[ "$probe_rc" -eq 0 ]
