#!/usr/bin/env bash
# IPv4 policy for a dedicated scheme 3 guest; never flush a shared routing table.
set -euo pipefail
export LC_ALL=C

# unused rejects a table or rule priority already in use, before adding our entries.
unused() {
    local table=$1 priority=$2 routes rules
    routes=$(ip -4 route show table "$table" 2>&1) || [[ $routes == *"FIB table does not exist"* ]] || return 1
    [[ -z $routes || $routes == *"FIB table does not exist"* ]] || return 1
    rules=$(ip -N -4 rule show) || return 1
    ! grep -Eq "(^$priority:|lookup $table([[:space:]]|$))" <<<"$rules"
}

# fw changes only rules tagged as belonging to the scheme 3 guest.
fw() {
    local op=$1
    shift
    iptables -w "$op" FORWARD "$@" -m comment --comment hestia-scheme3
}

# step installs or removes one rule. The drop guard is installed first and removed last.
step() {
    local id=$1 op=$2 flag=-I
    [[ $op == add ]] || flag=-D
    case $id in
        1) fw "$flag" -i wg-keenetic '!' -o hestia0 -j DROP ;;
        2) fw "$flag" -i wg-keenetic -o hestia0 -j ACCEPT ;;
        3) fw "$flag" -i hestia0 -o wg-keenetic -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT ;;
        4) ip -4 route "$op" unreachable default table 200 metric 32767 ;;
        5) ip -4 route "$op" unreachable default table 201 metric 32767 ;;
        6) ip -4 rule "$op" priority 1000 iif wg-keenetic lookup 200 ;;
        7) ip -4 rule "$op" priority 1001 iif hestia0 lookup 201 ;;
    esac
}

# undo removes only entries successfully installed by this invocation in reverse order.
undo() {
    local i
    for ((i = done_steps; i > 0; i--)); do step "$i" del || true; done
}

case ${1:-} in
    preflight)
        if ! unused 200 1000 || ! unused 201 1001; then
            echo 'Routing tables 200/201 or priorities 1000/1001 are in use.' >&2
            exit 1
        fi
        ;;
    wg-up)
        "$0" preflight
        # First establish a guard that also covers startup failures and TUN downtime.
        done_steps=0
        trap undo EXIT
        for i in {1..7}; do
            step "$i" add
            done_steps=$i
        done
        trap - EXIT
        ;;
    tun-up)
        ip -4 route add default dev hestia0 table 200 metric 100
        # These routes depend on WG, not TUN; keep them across sing-box restarts.
        for prefix in 10.253.241.1/32 192.168.1.0/24; do
            ip -4 route replace "$prefix" dev wg-keenetic table 201 metric 100
        done
        ;;
    wg-down)
        failed=0
        for i in {7..1}; do step "$i" del || failed=1; done
        exit "$failed"
        ;;
    *) exit 2 ;;
esac
