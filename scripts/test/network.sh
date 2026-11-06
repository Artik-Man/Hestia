#!/usr/bin/env bash
# Run one accepted local-only networking test on the already-running development VM.
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 2 && -n ${HESTIA_EXPECTED_HOSTNAME:-} && $(hostname -s) == "$HESTIA_EXPECTED_HOSTNAME" ]]
[[ ${HESTIA_VALIDATION_ROOT:-} =~ ^/var/tmp/hestia-validation-[A-Za-z0-9-]+$ ]]
[[ ! -L $HESTIA_VALIDATION_ROOT && $(stat -c %u "$HESTIA_VALIDATION_ROOT") == 0 && $(stat -c %a "$HESTIA_VALIDATION_ROOT") == 700 ]]
release=$HESTIA_VALIDATION_ROOT/bin
repo=$HESTIA_VALIDATION_ROOT/repo
name=$1
out=$2
[[ -d $repo/tests/lab && $out =~ ^/var/tmp/hestia-dev-network-[A-Za-z0-9_.-]+$ && ! -e $out && ! -L $out ]]
mkdir -m 0700 "$out"
box=$release/sing-box
unset HESTIA_WATCH HESTIA_UNDERLAYS
export SING_BOX=$box
LD_LIBRARY_PATH=$(dirname "$box")
PATH="$LD_LIBRARY_PATH:/usr/sbin:/usr/bin:/sbin:/bin"
export LD_LIBRARY_PATH PATH
printf 'case=%s\nartifact-directory=%s\n' "$name" "$release"
sha256sum "$release/hestia" "$release/amneziawg-go" "$release/awg" "$box"
# The private /run prevents named-netns files escaping into the host after an interrupted case.
# shellcheck disable=SC2016
common=(timeout --signal=TERM --kill-after=10s 600s unshare --mount --uts --net --pid --fork --mount-proc --propagation private --kill-child=KILL bash -ec 'hostname lima-hestia-dev; mount --make-rprivate /; mount -t tmpfs tmpfs /run; exec "$@"' _)
case $name in
    awg-multi)
        mkdir "$out/bundle"
        cp "$repo/tests/lab/awg-multi/"* "$out/bundle/"
        cp "$release/profile.py" "$out/bundle/profile.py"
        "${common[@]}" bash "$out/bundle/lab.sh" "$release/hestia" "$release/amneziawg-go" "$release/awg" "$box"
        ;;
    wg-default | wg-automatic | wg-native | wg-loss | wg-padding)
        extra=()
        case $name in
            wg-automatic) extra=(--automatic-control) ;;
            wg-native) extra=(--native-parent) ;;
            wg-loss) extra=(--udp-loss) ;;
            wg-padding) extra=(--awg-padding) ;;
        esac
        "${common[@]}" bash "$repo/tests/lab/wg-underlay/lab.sh" "$release/hestia" "$release/amneziawg-go" "$release/awg" "$box" "$release/profile.py" "${extra[@]}"
        ;;
    hysteria-plain | hysteria-watch | hysteria-ordered)
        if [[ $name != hysteria-plain ]]; then export HESTIA_WATCH=$release/hestia; fi
        if [[ $name == hysteria-ordered ]]; then export HESTIA_UNDERLAYS=ordered; fi
        "${common[@]}" bash "$repo/tests/lab/hysteria2/lab.sh"
        ;;
    controller-routing | group-quality)
        "${common[@]}" bash "$repo/tests/lab/$name/lab.sh" "$release/hestia" "$out/results"
        ;;
    partial-loss)
        "${common[@]}" bash "$repo/tests/lab/partial-loss/lab.sh" "$out/results"
        ;;
    physical-inventory)
        timeout 30s unshare --mount --uts --propagation private bash -ec 'hostname lima-hestia-dev; exec "$@"' _ bash "$repo/tests/lab/physical-connections/inventory.sh" "$release/hestia"
        ;;
    *) exit 2 ;;
esac
