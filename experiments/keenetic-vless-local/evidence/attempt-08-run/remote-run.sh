#!/bin/sh
set +e
W=/opt/tmp/hestia-vless-local.20261106-1905
cd "$W" || exit 80
umask 077
printf 'run_start_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if netstat -ln 2>/dev/null | grep -E ':1931[0-9] '; then
  printf 'reserved_port_conflict=present\n'
  exit 70
fi
printf 'reserved_port_conflict=none\n'
R4B=$(ip -4 route show table all | sha256sum | awk '{print $1}')
Q4B=$(ip -4 rule show | sha256sum | awk '{print $1}')
R6B=$(ip -6 route show table all | sha256sum | awk '{print $1}')
Q6B=$(ip -6 rule show | sha256sum | awk '{print $1}')
printf 'routes4_before=%s\nrules4_before=%s\nroutes6_before=%s\nrules6_before=%s\n' "$R4B" "$Q4B" "$R6B" "$Q6B"
: > pids
(
  sleep 45
  while read -r P; do
    [ -n "$P" ] && kill "$P" 2>/dev/null
  done < "$W/pids"
) >/dev/null 2>&1 &
WATCHDOG_PID=$!
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c vless-server.json > server.log 2>&1 &
SERVER_PID=$!
printf '%s\n' "$SERVER_PID" >> pids
sleep 1
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c vless-local.json > good-client.log 2>&1 &
GOOD_PID=$!
printf '%s\n' "$GOOD_PID" >> pids
sleep 1
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c vless-wrong-uuid.json > bad-client.log 2>&1 &
BAD_PID=$!
printf '%s\n' "$BAD_PID" >> pids
sleep 1
printf 'singbox_pids server=%s good_uuid_client=%s wrong_uuid_client=%s watchdog=%s\n' "$SERVER_PID" "$GOOD_PID" "$BAD_PID" "$WATCHDOG_PID"
printf 'command=./hestia-vless-local-harness -duration=35s -server-pid=%s -good-client-pid=%s -bad-client-pid=%s\n' "$SERVER_PID" "$GOOD_PID" "$BAD_PID"
./hestia-vless-local-harness -duration=35s -server-pid="$SERVER_PID" -good-client-pid="$GOOD_PID" -bad-client-pid="$BAD_PID" > harness.log 2>&1
HARNESS_RC=$?
printf 'harness_stdout_stderr_begin\n'
cat harness.log
printf 'harness_stdout_stderr_end\nharness_exit=%s\n' "$HARNESS_RC"
printf 'server_stdout_stderr_begin\n'
sed -E '/(updated default interface|default route|gateway|interface.*selected)/s|.*|[redacted: topology-bearing interface detail]|' server.log
printf 'server_stdout_stderr_end\ngood_client_stdout_stderr_begin\n'
sed -E '/(updated default interface|default route|gateway|interface.*selected)/s|.*|[redacted: topology-bearing interface detail]|' good-client.log
printf 'good_client_stdout_stderr_end\nwrong_uuid_client_stdout_stderr_begin\n'
sed -E '/(updated default interface|default route|gateway|interface.*selected)/s|.*|[redacted: topology-bearing interface detail]|' bad-client.log
printf 'wrong_uuid_client_stdout_stderr_end\n'
for P in "$SERVER_PID" "$GOOD_PID" "$BAD_PID"; do kill "$P" 2>/dev/null; done
wait "$SERVER_PID" 2>/dev/null
wait "$GOOD_PID" 2>/dev/null
wait "$BAD_PID" 2>/dev/null
kill "$WATCHDOG_PID" 2>/dev/null
wait "$WATCHDOG_PID" 2>/dev/null
printf 'owned_processes_absent='
ABSENT=yes
for P in "$SERVER_PID" "$GOOD_PID" "$BAD_PID" "$WATCHDOG_PID"; do
  if kill -0 "$P" 2>/dev/null; then ABSENT=no; fi
done
printf '%s\n' "$ABSENT"
printf 'reserved_listeners_after=';
if netstat -ln 2>/dev/null | grep -E ':1931[0-9] '; then :; else printf 'none\n'; fi
R4A=$(ip -4 route show table all | sha256sum | awk '{print $1}')
Q4A=$(ip -4 rule show | sha256sum | awk '{print $1}')
R6A=$(ip -6 route show table all | sha256sum | awk '{print $1}')
Q6A=$(ip -6 rule show | sha256sum | awk '{print $1}')
printf 'routes4_after=%s\nrules4_after=%s\nroutes6_after=%s\nrules6_after=%s\n' "$R4A" "$Q4A" "$R6A" "$Q6A"
if [ "$R4B" = "$R4A" ] && [ "$Q4B" = "$Q4A" ] && [ "$R6B" = "$R6A" ] && [ "$Q6B" = "$Q6A" ]; then
  printf 'route_rule_hashes_match=yes\n'
else
  printf 'route_rule_hashes_match=no\n'
  HARNESS_RC=71
fi
printf 'run_end_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
exit "$HARNESS_RC"
