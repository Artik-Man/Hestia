#!/usr/bin/env bash
# Run inside the gateway/client/peer fixture from dynamic-exception/lab.sh.

# wait_report waits for a specific recent observer result, failing on timeout or controller exit.
wait_report() {
    timeout 15 python3 "$ROOT/../steer/check.py" wait "$OUT" "$1" "$2" "$3" || {
        cat "$OUT/steer.stderr" >&2
        return 1
    }
}

# steer_phases observes FI paths continuously, induces selective loss, and traces fresh client flows.
steer_phases() {
    local ctl x
    x=$(<"$OUT/discovered.txt")
    ctl=$(realpath "${HESTIA_BIN:?supply the compiled ARM64 Hestia binary}")
    python3 "$ROOT/../steer/check.py" config "$OUT"
    ip netns exec "$S" python3 -B "$ROOT/../steer/check.py" echo "$OUT" >echo.log 2>&1 &
    for _ in {1..100}; do
        grep -qs READY echo.log && break
        sleep .05
    done
    grep -q READY echo.log
    ip netns exec "$G" "$ctl" steer -config "$OUT/measure.json" -rules "$OUT/fi-udp.json" >decisions.jsonl 2>steer.stderr &
    local daemon=$!
    wait_report fi1 equal unchanged
    local loss=(-p udp -d "$x" -m statistic --mode nth --every 2 --packet 0 -j DROP)
    svc iptables -I INPUT -i via-fi1 "${loss[@]}"
    event "impaired via-fi1 UDP/$x"
    wait_report fi2 loss added
    client await "$OUT/records.json" "$OUT/state.json" fi2 >>barrier.jsonl
    phase automatic
    svc iptables -nvxL INPUT >loss-firewall.txt
    svc iptables -D INPUT -i via-fi1 "${loss[@]}"
    event "recovered via-fi1"
    wait_report fi2 equal unchanged
    phase tie
    svc iptables -I INPUT -i via-fi2 "${loss[@]}"
    event "impaired via-fi2 UDP/$x"
    wait_report fi1 loss removed
    client await "$OUT/records.json" "$OUT/state.json" fi1 >>barrier.jsonl
    phase retired
    svc iptables -nvxL INPUT >reverse-firewall.txt
    svc iptables -D INPUT -i via-fi2 "${loss[@]}"
    kill -TERM "$daemon"
    wait "$daemon"
    sha256sum "$ctl" | cut -d' ' -f1 >controller.sha256
}
