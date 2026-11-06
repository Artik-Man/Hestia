#!/bin/sh
# Run bounded local Hysteria 2 authentication and marker probes with exact-PID cleanup.
set -eu
umask 077

if [ "$#" -ne 1 ]; then
	printf 'usage: run-hy2-study.sh /opt/tmp/hestia-hy2-local.<suffix>\n' >&2
	exit 2
fi
work=$1
case $work in
/opt/tmp/hestia-hy2-local.*) ;;
*)
	printf 'refusing unexpected work directory\n' >&2
	exit 2
	;;
esac
cd "$work"

route4_before=$(ip -4 route show table all | sha256sum | cut -d ' ' -f 1)
rules4_before=$(ip -4 rule show | sha256sum | cut -d ' ' -f 1)
route6_before=$(ip -6 route show table all | sha256sum | cut -d ' ' -f 1)
rules6_before=$(ip -6 rule show | sha256sum | cut -d ' ' -f 1)
server_pid=
marker_pid=
bad_client_pid=
good_client_pid=
watchdog_pid=

# cleanup terminates only PIDs started by this invocation and records hash-only route/rule comparisons.
cleanup() {
	result=$?
	trap - EXIT HUP INT TERM
	set +e
	for pid in "$bad_client_pid" "$good_client_pid" "$server_pid" "$marker_pid"; do
		if [ -n "$pid" ]; then
			kill -TERM "$pid" 2>/dev/null
		fi
	done
	for pid in "$bad_client_pid" "$good_client_pid" "$server_pid" "$marker_pid"; do
		if [ -n "$pid" ]; then
			wait "$pid" 2>/dev/null
		fi
	done
	if [ -n "$watchdog_pid" ]; then
		kill "$watchdog_pid" 2>/dev/null
		wait "$watchdog_pid" 2>/dev/null
	fi
	route4_after=$(ip -4 route show table all | sha256sum | cut -d ' ' -f 1)
	rules4_after=$(ip -4 rule show | sha256sum | cut -d ' ' -f 1)
	route6_after=$(ip -6 route show table all | sha256sum | cut -d ' ' -f 1)
	rules6_after=$(ip -6 rule show | sha256sum | cut -d ' ' -f 1)
	{
		printf 'routes4_before=%s\nroutes4_after=%s\n' "$route4_before" "$route4_after"
		printf 'rules4_before=%s\nrules4_after=%s\n' "$rules4_before" "$rules4_after"
		printf 'routes6_before=%s\nroutes6_after=%s\n' "$route6_before" "$route6_after"
		printf 'rules6_before=%s\nrules6_after=%s\n' "$rules6_before" "$rules6_after"
		printf 'owned_pids_absent='
		absent=yes
		for pid in "$bad_client_pid" "$good_client_pid" "$server_pid" "$marker_pid"; do
			if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
				absent=no
			fi
		done
		printf '%s\n' "$absent"
		printf 'cleanup_exit=%s\n' "$result"
	} >cleanup.txt
	cat cleanup.txt
	if [ "$route4_before" != "$route4_after" ] || [ "$rules4_before" != "$rules4_after" ] || [ "$route6_before" != "$route6_after" ] || [ "$rules6_before" != "$rules6_after" ] || [ "$absent" != yes ]; then
		exit 1
	fi
}
trap cleanup EXIT HUP INT TERM

(
	sleep 75
	for pidfile in server.pid marker.pid bad-client.pid good-client.pid; do
		if [ -f "$work/$pidfile" ]; then
			kill -TERM "$(cat "$work/$pidfile")" 2>/dev/null
		fi
	done
	sleep 2
	rm -rf "$work"
) </dev/null >/dev/null 2>&1 &
watchdog_pid=$!
printf 'run_start_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf 'workdir=%s\n' "$work"
printf 'sing_box_sha256='
sha256sum ./sing-box | cut -d ' ' -f 1
printf 'helper_sha256='
sha256sum ./hestia-hy2-harness | cut -d ' ' -f 1
for config in server.json client-bad-auth.json client-good.json; do
	printf 'config_sha256 file=%s sha256=' "$config"
	sha256sum "$config" | cut -d ' ' -f 1
	/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box check -c "$config"
done
/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box version

/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c server.json >server.log 2>&1 &
server_pid=$!
printf '%s\n' "$server_pid" >server.pid
./hestia-hy2-harness -mode serve -duration 40s >markers.log 2>&1 &
marker_pid=$!
printf '%s\n' "$marker_pid" >marker.pid
attempt=0
while ! grep -q 'sing-box started' server.log || ! grep -q 'endpoints_ready' markers.log; do
	if ! kill -0 "$server_pid" 2>/dev/null || ! kill -0 "$marker_pid" 2>/dev/null; then
		printf 'service_start=failed\n'
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 15 ]; then
		printf 'service_start=timeout\n'
		exit 1
	fi
	sleep 1
done
printf 'service_start=ready server_pid=%s marker_pid=%s\n' "$server_pid" "$marker_pid"

/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c client-bad-auth.json >client-bad-auth.log 2>&1 &
bad_client_pid=$!
printf '%s\n' "$bad_client_pid" >bad-client.pid
attempt=0
while ! grep -q 'sing-box started' client-bad-auth.log; do
	if ! kill -0 "$bad_client_pid" 2>/dev/null; then
		printf 'bad_auth_client_start=failed\n'
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 15 ]; then
		printf 'bad_auth_client_start=timeout\n'
		exit 1
	fi
	sleep 1
done
./hestia-hy2-harness -mode bad-auth -server-pid "$server_pid" -duration 12s >bad-auth-probe.log 2>&1
cat bad-auth-probe.log
kill -TERM "$bad_client_pid"
wait "$bad_client_pid" 2>/dev/null || true
bad_client_pid=
printf 'bad_auth_client_stopped=yes\n'

/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c client-good.json >client-good.log 2>&1 &
good_client_pid=$!
printf '%s\n' "$good_client_pid" >good-client.pid
attempt=0
while ! grep -q 'sing-box started' client-good.log; do
	if ! kill -0 "$good_client_pid" 2>/dev/null; then
		printf 'valid_client_start=failed\n'
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 15 ]; then
		printf 'valid_client_start=timeout\n'
		exit 1
	fi
	sleep 1
done
./hestia-hy2-harness -mode positive -server-pid "$server_pid" -duration 18s >positive-probe.log 2>&1
cat positive-probe.log
printf 'run_end_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
cat server.log markers.log client-bad-auth.log client-good.log
