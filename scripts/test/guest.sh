#!/usr/bin/env bash
# Check copied installed Linux runtimes without modifying the selected stand's configuration.
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 4 ]]
root=$1
phase=$2
expected=$3
panel=$4
[[ $(hostname -s) == "$expected" && $(uname -m) == aarch64 ]]
[[ $root =~ ^/var/tmp/hestia-validation-[A-Za-z0-9-]+$ && ! -L $root && $(stat -c %u "$root") == 0 && $(stat -c %a "$root") == 700 ]]
repo=$root/repo
# snapshot stores private identities only; no live configuration is exported or restored.
snapshot() {
    local suffix=$1
    [[ -z $(find /etc/hestia -type l -o -type b -o -type c -o -type p -o -type s) ]]
    find /etc/hestia -type f -exec sha256sum {} + | sort >"$root/config$suffix"
    ip -4 route show table main >"$root/routes4$suffix"
    ip -6 route show table main >"$root/routes6$suffix"
    ip -4 rule show >"$root/rules4$suffix"
    ip -6 rule show >"$root/rules6$suffix"
    ip netns list | sort >"$root/netns$suffix"
}
case $phase in
    prepare)
        for tool in ip tcpdump iptables openssl curl python3 timeout unshare sha256sum sudo flock systemctl; do command -v "$tool" >/dev/null || {
            echo "Missing required stand dependency: $tool"
            exit 2
        }; done
        python3 -c 'import dns'
        [[ -c /dev/net/tun ]]
        mkdir "$root/bin"
        for name in hestia hestia-panel hestia-observe awg; do cp "/usr/local/bin/$name" "$root/bin/$name"; done
        for name in amneziawg-go sing-box profile.py; do cp "/usr/local/lib/hestia/$name" "$root/bin/$name"; done
        # Historical Hysteria fixture resolves its compiler via repo/deploy; use the installed copy.
        mkdir -p "$repo/deploy"
        cp "$root/bin/profile.py" "$repo/deploy/profile.py"
        sha256sum /usr/local/bin/{hestia,hestia-panel,hestia-observe,awg} /usr/local/lib/hestia/{amneziawg-go,sing-box,profile.py} >"$root/installed.sha256"
        HESTIA_LIBCRONET=/usr/local/lib/hestia/libcronet.so
        if [[ -f $HESTIA_LIBCRONET ]]; then
            [[ $HESTIA_LIBCRONET == /* && -f $HESTIA_LIBCRONET && ! -L $HESTIA_LIBCRONET ]]
            cp "$HESTIA_LIBCRONET" "$root/bin/libcronet.so"
            sha256sum "$HESTIA_LIBCRONET" >>"$root/installed.sha256"
        fi
        [[ -d /usr/local/share/hestia-panel/current && ! -L /usr/local/share/hestia-panel/current ]]
        find /usr/local/lib/hestia /usr/local/share/hestia-panel/current -type f -exec sha256sum {} + >>"$root/installed.sha256"
        find /usr/local/lib/hestia /usr/local/share/hestia-panel/current -printf '%y %p\n' | sort >"$root/installed-inventory"
        cat "$root/installed.sha256"
        snapshot ''
        printf 'PASS actual stand=%s; private labs use compatibility hostname lima-hestia-dev\n' "$expected"
        ;;
    acceptance)
        python3 "$repo/scripts/test/read_only.py" "$panel"
        work=$(mktemp -d "$root/isolated.XXXXXXXX")
        trap 'rm -rf -- "$work"' EXIT
        mkdir "$work/quality" "$work/dns"
        cp "$repo/tests/lab/connection-quality/"{run.sh,respond.py,verify.py} "$work/quality/"
        cp "$root/quality-test-service" "$work/quality/quality-test-service"
        for target in quality dns; do
            cp "$root/bin/"{hestia,hestia-panel,sing-box,profile.py} "$work/$target/"
            chmod 0755 "$work/$target/"{hestia,hestia-panel,sing-box}
            if [[ -f $root/bin/libcronet.so ]]; then cp "$root/bin/libcronet.so" "$work/$target/"; fi
        done
        cp "$repo/tests/lab/dns-panel/verify.py" "$work/dns/verify.py"
        failed=0
        rc=0
        (cd "$work/quality" && LD_LIBRARY_PATH="$work/quality" timeout --kill-after=10s 180s unshare --mount --uts --net --pid --fork --mount-proc --kill-child=KILL bash -ec 'hostname lima-hestia-dev; exec bash run.sh') >"$root/quality.log" 2>&1 || rc=$?
        for name in panel backend worker; do
            if [[ -f $work/quality/$name.log ]]; then cp "$work/quality/$name.log" "$root/quality-$name.log"; fi
        done
        if ((rc == 0)); then echo 'PASS copied installed runtime: quality/carrier failover (source measurement fixture)'; else
            echo "FAIL isolated-quality exit=$rc; see quality logs"
            failed=1
        fi
        rc=0
        LD_LIBRARY_PATH="$work/dns" timeout --kill-after=10s 60s unshare --net python3 "$work/dns/verify.py" "$work/dns" >"$root/dns.log" 2>&1 || rc=$?
        if ((rc == 0)); then echo 'PASS copied installed runtime: isolated panel/DNS CRUD and deny'; else
            echo "FAIL isolated-panel-dns exit=$rc; see dns.log"
            failed=1
        fi
        exit "$failed"
        ;;
    network)
        export HESTIA_VALIDATION_ROOT=$root HESTIA_EXPECTED_HOSTNAME=$expected
        failed=0
        for name in awg-multi wg-default wg-automatic wg-native wg-loss wg-padding hysteria-plain hysteria-watch hysteria-ordered controller-routing group-quality physical-inventory partial-loss; do
            rc=0
            bash "$repo/scripts/test/network.sh" "$name" "/var/tmp/hestia-dev-network-$(basename "$root")-$name" >"$root/$name.log" 2>&1 || rc=$?
            if ((rc == 0)); then echo "PASS $name"; elif ((rc == 77)); then
                echo "SKIP $name: capability unavailable; coverage incomplete"
                failed=1
            else
                echo "FAIL $name exit=$rc"
                failed=1
            fi
        done
        exit "$failed"
        ;;
    final)
        sha256sum -c "$root/installed.sha256"
        find /usr/local/lib/hestia /usr/local/share/hestia-panel/current -printf '%y %p\n' | sort >"$root/installed-inventory.after"
        cmp "$root/installed-inventory" "$root/installed-inventory.after"
        snapshot '.after'
        for name in config routes4 routes6 rules4 rules6 netns; do cmp "$root/$name" "$root/$name.after"; done
        echo 'PASS installed hashes/config/main routes/rules/namespaces preserved'
        ;;
    *) exit 2 ;;
esac
