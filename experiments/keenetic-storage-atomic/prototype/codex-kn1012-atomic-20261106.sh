#!/bin/sh
# Run only on KN-1012 after the coordinator opens the remote-access gate.
set -eu

work=/opt/tmp/codex-kn1012-atomic-20261106
target="$work/marker"
next="$work/marker.next"
done_flag="$work/reader.done"
reader_ready="$work/reader.ready"
reader_result="$work/reader.result"
marker_a='codex-kn1012-atomic-20261106:A:synthetic'
marker_b='codex-kn1012-atomic-20261106:B:synthetic'

# fail prints a bounded diagnostic and exits without removing unknown files.
fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

# read_marker accepts only a whole expected synthetic marker.
read_marker() {
	value=$(cat "$target") || fail 'cannot read marker'
	[ "$value" = "$marker_a" ] || [ "$value" = "$marker_b" ] || fail 'unexpected or partial marker'
}

# stop_reader signals and waits for only the reader started by this script.
stop_reader() {
	if [ -n "${reader_pid:-}" ]; then
		: > "$done_flag"
		wait "$reader_pid" 2>/dev/null || :
	fi
}

[ "$work" = /opt/tmp/codex-kn1012-atomic-20261106 ] || fail 'unexpected work path'
[ ! -e "$work" ] || fail 'reserved work directory already exists'
umask 077
mkdir -m 700 "$work" || fail 'cannot create private work directory'
[ "$(stat -c '%a' "$work")" = 700 ] || fail 'unexpected work directory mode'

printf '%s\n' "$marker_a" > "$target"
chmod 600 "$target"
[ "$(stat -c '%a' "$target")" = 600 ] || fail 'unexpected initial marker mode'

# The reader is bounded by a fixed iteration cap and stops after the writer flag.
(
	set -eu
	count=0
	: > "$reader_ready"
	while [ "$count" -lt 10000 ] && [ ! -e "$done_flag" ]; do
		value=$(cat "$target") || exit 21
		if [ "$value" != "$marker_a" ] && [ "$value" != "$marker_b" ]; then
			printf 'partial-or-unexpected\n' > "$reader_result"
			exit 22
		fi
		count=$((count + 1))
	done
	printf 'reads=%s\n' "$count" > "$reader_result"
) &
reader_pid=$!
trap stop_reader EXIT
trap 'stop_reader; exit 1' HUP INT TERM

# Wait a bounded time for the reader to start before replacing the marker.
wait_count=0
while [ ! -e "$reader_ready" ] && [ "$wait_count" -lt 5 ]; do
	sleep 1
	wait_count=$((wait_count + 1))
done
[ -e "$reader_ready" ] || fail 'reader did not start within five seconds'
sleep 1
kill -0 "$reader_pid" 2>/dev/null || fail 'reader ended before replacement began'

# Replace the same regular file from a temporary file in the same directory.
i=1
while [ "$i" -le 32 ]; do
	if [ $((i % 2)) -eq 1 ]; then value=$marker_b; else value=$marker_a; fi
	printf '%s\n' "$value" > "$next"
	chmod 600 "$next"
	mv -f "$next" "$target"
	read_marker
	i=$((i + 1))
done

printf 'done\n' > "$done_flag"
wait "$reader_pid" || fail 'bounded reader detected unexpected content'
reader_pid=
[ -f "$reader_result" ] || fail 'reader produced no result'
read_marker
[ "$(stat -c '%a' "$target")" = 600 ] || fail 'unexpected final marker mode'
sha256sum "$target"
cat "$reader_result"
printf 'replacement=passed\n'

# Remove only known files; rmdir refuses cleanup if any unexpected entry remains.
trap - EXIT HUP INT TERM
rm -f "$target" "$next" "$done_flag" "$reader_ready" "$reader_result"
rmdir "$work" || fail 'work directory is not empty; preserve it for inspection'
[ ! -e "$work" ] || fail 'work directory remains after cleanup'
printf 'cleanup=passed\n'
