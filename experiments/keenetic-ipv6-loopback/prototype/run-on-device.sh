#!/bin/sh
# Run the bounded IPv6 loopback harness with an owned sing-box process and watchdog.
set -u

workdir=/opt/tmp/kn1012-ipv6-loopback-20261106-01
cd "$workdir" || exit 20

singbox_pid=
harness_pid=
watchdog_pid=

# shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap.
# cleanup stops only child PIDs started by this runner and waits for their exit.
cleanup() {
  if [ -n "$watchdog_pid" ]; then
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
  fi
  if [ -n "$harness_pid" ]; then
    if kill -0 "$harness_pid" 2>/dev/null; then
      kill -TERM "$harness_pid" 2>/dev/null || true
    fi
    wait "$harness_pid" 2>/dev/null || true
  fi
  if [ -n "$singbox_pid" ]; then
    command_line=$(tr '\000' ' ' <"/proc/$singbox_pid/cmdline" 2>/dev/null || true)
    case "$command_line" in
    *singbox-ipv6-loopback.json*)
      kill -TERM "$singbox_pid" 2>/dev/null || true
      wait "$singbox_pid" 2>/dev/null || true
      ;;
    esac
  fi
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if netstat -lnptu 2>/dev/null | awk '$4 ~ /:(19430|19431|19432|19433|19434|19435|19436|19437|19438|19439)$/ {found=1} END {exit !found}'; then
  echo 'pre-run port conflict in assigned range' >&2
  exit 21
fi

/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box run -c singbox-ipv6-loopback.json >sing-box.log 2>&1 &
singbox_pid=$!
echo "singbox_pid=$singbox_pid"

ready=0
attempt=0
while [ "$attempt" -lt 5 ]; do
  if grep -F 'inbound/socks[ipv6-loopback-socks]: tcp server started at [::1]:19430' sing-box.log >/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$singbox_pid" 2>/dev/null; then
    echo 'sing-box exited before SOCKS listener became ready' >&2
    exit 22
  fi
  attempt=$((attempt + 1))
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo 'SOCKS listener did not become ready within 5 seconds' >&2
  exit 23
fi

./hestia-ipv6-loopback-harness -duration=35s -daemon-pid="$singbox_pid" &
harness_pid=$!
echo "harness_pid=$harness_pid"
# watchdog terminates only this runner's harness and sing-box children after 39 seconds.
(
  sleep 39
  if [ -n "$harness_pid" ] && kill -0 "$harness_pid" 2>/dev/null; then
    kill -TERM "$harness_pid" 2>/dev/null || true
  fi
  if [ -n "$singbox_pid" ] && kill -0 "$singbox_pid" 2>/dev/null; then
    command_line=$(tr '\000' ' ' <"/proc/$singbox_pid/cmdline" 2>/dev/null || true)
    case "$command_line" in
    *singbox-ipv6-loopback.json*) kill -TERM "$singbox_pid" 2>/dev/null || true ;;
    esac
  fi
) &
watchdog_pid=$!
echo "watchdog_pid=$watchdog_pid timeout_seconds=39"
set +e
wait "$harness_pid"
result=$?
set -e
harness_pid=
echo "harness_exit_code=$result"
exit "$result"
