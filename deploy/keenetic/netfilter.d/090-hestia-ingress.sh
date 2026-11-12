#!/bin/sh
# Reconcile Hestia's policy routes synchronously after Keenetic rebuilds IPv4 mangle rules.

set -eu

[ "${type:-}" = iptables ] || exit 0
[ "${table:-}" = mangle ] || exit 0
MAINTENANCE=/opt/var/run/hestia/package-maintenance
if [ -e "$MAINTENANCE" ] || [ -L "$MAINTENANCE" ]; then
    if [ -f "$MAINTENANCE" ] && [ ! -L "$MAINTENANCE" ]; then
        MARKER_PID=
        MARKER_BOOT=
        MARKER_START=
        MARKER_EXTRA=
        IFS=' ' read -r MARKER_PID MARKER_BOOT MARKER_START MARKER_EXTRA <"$MAINTENANCE" || :
        BOOT_ID=$(/opt/bin/busybox cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
        MARKER_LINES=$(/opt/bin/busybox wc -l <"$MAINTENANCE" 2>/dev/null || printf '0')
        MARKER_TAIL=$(sed -n '2,$p' "$MAINTENANCE" 2>/dev/null || true)
        MARKER_META=$(/opt/bin/busybox stat -c '%u %a %h %s' "$MAINTENANCE" 2>/dev/null || true)
        MARKER_EXPECTED_SIZE=$(printf '%s %s %s\n' "$MARKER_PID" "$MARKER_BOOT" "$MARKER_START" | /opt/bin/busybox wc -c)
        IFS=' ' read -r MARKER_UID MARKER_MODE MARKER_LINKS MARKER_SIZE MARKER_META_EXTRA <<EOF
$MARKER_META
EOF
        case "$MARKER_PID" in
            '' | 0* | 1 | *[!0-9]*) ;;
            *)
                case "$MARKER_START" in
                    '' | 0* | *[!0-9]*) continue_marker=0 ;;
                    *)
                        if [ "$MARKER_START" -gt 0 ] 2>/dev/null; then
                            continue_marker=1
                        else
                            continue_marker=0
                        fi
                        ;;
                esac
                if [ "$MARKER_LINES" -eq 1 ] 2>/dev/null && [ -z "$MARKER_TAIL" ] && [ "$MARKER_SIZE" = "$MARKER_EXPECTED_SIZE" ] && [ "$MARKER_UID" = 0 ] && [ "$MARKER_MODE" = 600 ] && [ "$MARKER_LINKS" = 1 ] && [ -z "$MARKER_META_EXTRA" ] && [ "$MARKER_SIZE" -le 128 ] 2>/dev/null && [ "$continue_marker" = 1 ] && [ -z "$MARKER_EXTRA" ] && [ "$MARKER_BOOT" = "$BOOT_ID" ] && [ -r "/proc/$MARKER_PID/comm" ] && [ -r "/proc/$MARKER_PID/stat" ]; then
                    read -r MARKER_COMM <"/proc/$MARKER_PID/comm" || MARKER_COMM=
                    case "$MARKER_COMM" in
                        opkg | opkg-cl)
                            PROCESS_START=$(sed 's/^.*) //' "/proc/$MARKER_PID/stat" 2>/dev/null | awk '{ print $20 }')
                            case "$PROCESS_START" in
                                '' | *[!0-9]*) ;;
                                *)
                                    if [ "$PROCESS_START" -gt 0 ] 2>/dev/null && [ "$PROCESS_START" = "$MARKER_START" ]; then
                                        exit 0
                                    fi
                                    ;;
                            esac
                            ;;
                    esac
                fi
                ;;
        esac
    fi
fi
[ -x /opt/bin/hestia ] || {
    printf '%s\n' 'Hestia netfilter hook has no executable' >&2
    exit 1
}
[ -s /opt/etc/hestia/keenetic-rci-token ] || {
    printf '%s\n' 'Hestia netfilter hook has no RCI token' >&2
    exit 1
}

# The command falls back to a serialized guard-only reconciliation if the supervisor is unavailable.
exec /opt/bin/hestia -service-reconcile-ingress
