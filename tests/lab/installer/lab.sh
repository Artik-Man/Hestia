#!/usr/bin/env bash
# Only on a fresh disposable Debian ARM64 guest whose PID 1 is systemd.
set -euo pipefail
umask 077
[[ $# == 4 && $EUID == 0 && $(dpkg --print-architecture) == arm64 ]]
mode=$1
ctl=$(realpath "$2")
archive=$(realpath "$3")
out=$(realpath -m "$4")
root=$(cd "$(dirname "$0")/../../.." && pwd)
# install_hestia runs the installer with the trusted ARM64 controller and supplied backend archive.
install_hestia() {
    bash "$root/deploy/install.sh" --controller-binary "$ctl" --sing-box-archive "$1"
}
resources=(/etc/hestia/snapshot.json /etc/hestia/sing-box.json)
services=(hestia-sing-box.service hestia.service)
# selector returns the currently selected bootstrap outbound from the loopback Clash API.
selector() {
    curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:9090/proxies/bootstrap |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["now"])'
}
# assert_ready checks that both units are enabled and active, then waits for the expected bootstrap target.
assert_ready() {
    local expected=$1
    for unit in "${services[@]}"; do
        [[ $(systemctl is-enabled "$unit") == enabled ]]
        systemctl is-active --quiet "$unit"
    done
    for _ in {1..80}; do
        [[ $(selector 2>/dev/null) == "$expected" ]] && return 0
        sleep .25
    done
    echo "Expected selector bootstrap=$expected" >&2
    return 1
}
# save_state archives service PIDs, unit state and selector for comparing restart or rollback results.
save_state() {
    local stage=$1
    for unit in "${services[@]}"; do
        systemctl show "$unit" --property Id,MainPID,ActiveState,UnitFileState,ExecMainStatus
    done >"$out/$stage-units.txt"
    selector >"$out/$stage-selector.txt"
}
# http_control tests an actual HTTP request through the configured loopback SOCKS frontend.
http_control() {
    # This listener and the SOCKS frontend exist on guest loopback only.
    rm -f -- "$out/http-port"
    python3 -u - "$out" <<'PY' >"$out/http-port" &
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    """Return a recognizable service response for the loopback path test."""

    def do_GET(self):
        """Return the expected text used to verify delivery through SOCKS."""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hestia installer loopback test\n")
    def log_message(self, *args):
        """Silence request logs so only the bound port is collected by the harness."""
        pass
server = HTTPServer(("127.0.0.1", 0), Handler)
print(server.server_port, flush=True)
server.serve_forever()
PY
    server=$!
    trap 'kill "$server" 2>/dev/null || true' EXIT
    for _ in {1..50}; do
        [[ -s "$out/http-port" ]] && break
        sleep .05
    done
    curl --fail --silent --show-error --max-time 5 --noproxy '' \
        --socks5-hostname 127.0.0.1:19090 "http://127.0.0.1:$(cat "$out/http-port")/" |
        grep -Fx 'hestia installer loopback test'
    kill "$server"
    wait "$server" 2>/dev/null || true
    trap - EXIT
}
# customize adds a private test listener and outbound to the installed files for the preservation check.
customize() {
    python3 - "${resources[@]}" <<'PY'
from pathlib import Path
import json, sys
snapshot, core = map(Path, sys.argv[1:])
cfg = json.loads(snapshot.read_text())
group = next(g for g in cfg["groups"] if g["id"] == "bootstrap")
group["exits"] = ["operator-test"]
cfg["healthy"]["operator-test"] = True
snapshot.write_text(json.dumps(cfg, indent=2) + "\n")
cfg = json.loads(core.read_text())
sel = next(o for o in cfg["outbounds"] if o["tag"] == "bootstrap")
sel["outbounds"].append("operator-test")
cfg["outbounds"].append({"type":"direct", "tag":"operator-test"})
cfg.setdefault("inbounds", []).append({"type":"socks", "tag":"operator-test-in",
                                      "listen":"127.0.0.1", "listen_port":19090})
cfg.setdefault("route", {}).setdefault("rules", []).insert(0, {
    "inbound":["operator-test-in"], "action":"route", "outbound":"bootstrap"
})
core.write_text(json.dumps(cfg, indent=2) + "\n")
PY
}
# bad_runtime installs against a valid snapshot incompatible with the running selector and checks the smoke failure.
bad_runtime() {
    # This valid local snapshot references an exit absent from the running selector.
    # Existing config is operator-owned, so preserve its mismatch for the installer
    # to diagnose; restore the original after this negative test.
    local snapshot=${resources[0]}
    cp -p "$snapshot" "$out/last-good.snapshot"
    trap 'cat "$out/last-good.snapshot" > "${resources[0]}"' EXIT
    python3 - "$snapshot" <<'PYBAD'
import json,sys
from pathlib import Path
p = Path(sys.argv[1])
cfg = json.loads(p.read_text())
group = next(g for g in cfg["groups"] if g["id"] == "bootstrap")
group["exits"].insert(0, "missing-from-runtime")
cfg["healthy"]["missing-from-runtime"] = True
p.write_text(json.dumps(cfg) + "\n")
PYBAD
    if install_hestia "$archive" >"$out/bad-smoke.log" 2>&1; then
        echo 'Installer accepted an unreachable desired selector' >&2
        exit 1
    fi
    grep -qiE 'Smoke check failed|controller has not confirmed' "$out/bad-smoke.log" || {
        echo 'Negative test failed before the readiness smoke check' >&2
        exit 1
    }
    cat "$out/last-good.snapshot" >"$snapshot"
    trap - EXIT
    rm "$out/last-good.snapshot"
    sha256sum --check "$out/operator-config.sha256" >"$out/negative-restored.txt"
    systemctl restart hestia.service
    assert_ready operator-test
}
# bad_permissions makes backend secrets publicly readable in the isolated guest and tests that installation refuses to proceed.
bad_permissions() {
    local before
    before=$(systemctl show hestia.service hestia-sing-box.service -p MainPID --value)
    chmod 644 /etc/hestia/sing-box.json
    trap 'chmod 600 /etc/hestia/sing-box.json' EXIT
    if install_hestia "$archive" >"$out/public-backend.log" 2>&1; then
        echo "Installer accepted publicly readable private backend config" >&2
        exit 1
    fi
    grep -q 'backend configuration contains secrets and must be root-only' "$out/public-backend.log"
    [[ $before == "$(systemctl show hestia.service hestia-sing-box.service -p MainPID --value)" ]]
    chmod 600 /etc/hestia/sing-box.json
    trap - EXIT
    sha256sum --check "$out/operator-config.sha256" >"$out/public-backend-preserved.txt"
    assert_ready operator-test
}
case $mode in
    first)
        mkdir -p "$out"
        [[ -z $(ls -A "$out") ]]
        for f in /usr/local/bin/hestia /etc/hestia /etc/systemd/system/hestia.service; do
            [[ ! -e $f ]] || {
                echo "Use a clean guest: $f already exists" >&2
                exit 1
            }
        done
        { # shellcheck source=/dev/null
            . /etc/os-release
            echo "$PRETTY_NAME"
            uname -srm
            systemctl --version | head -1
        } >"$out/guest.txt"
        cat /proc/sys/kernel/random/boot_id >"$out/first-boot-id"
        ip -4 route show default >"$out/initial-default-route"
        printf '%s\n' 'tampered synthetic archive' >"$out/bad.tgz"
        if install_hestia "$out/bad.tgz" >"$out/bad-install.log" 2>&1; then
            echo 'Installer accepted invalid archive' >&2
            exit 1
        fi
        [[ ! -e /usr/local/bin/hestia && ! -e /etc/systemd/system/hestia.service ]]
        rm "$out/bad.tgz"
        install_hestia "$archive" >"$out/first-install.log" 2>&1
        assert_ready deny
        grep -q 'PASS:' "$out/first-install.log"
        ip -4 route show default | cmp - "$out/initial-default-route"
        save_state initial
        /usr/local/bin/hestia-export-config "$out/bootstrap-export.json"
        [[ $(stat -c %a "$out/bootstrap-export.json") == 600 ]]
        python3 -c 'import json,sys; assert json.load(open(sys.argv[1])) == {"version":1,"mode":"bootstrap"}' "$out/bootstrap-export.json"
        sha256sum "$out/bootstrap-export.json" >"$out/bootstrap-export.sha256"
        if /usr/local/bin/hestia-export-config "$out/bootstrap-export.json" >"$out/overwrite.log" 2>&1; then
            echo "Exporter overwrote an existing file" >&2
            exit 1
        fi
        sha256sum --check "$out/bootstrap-export.sha256"
        systemctl show hestia.service -p Wants -p After >"$out/hestia-dependencies.txt"
        ! grep -Eq '(^|[ =])sing-box.service([[:space:]]|$)' "$out/hestia-dependencies.txt" || exit 1
        customize
        systemctl restart hestia-sing-box.service hestia.service
        assert_ready operator-test
        http_control >"$out/first-http.txt"
        sha256sum "${resources[@]}" >"$out/operator-config.sha256"
        install_hestia "$archive" >"$out/repeat-install.log" 2>&1
        sha256sum --check "$out/operator-config.sha256" >"$out/repeat-preserved.txt"
        assert_ready operator-test
        grep -q 'PASS:' "$out/repeat-install.log"
        ip -4 route show default | cmp - "$out/initial-default-route"
        save_state repeat
        http_control >"$out/repeat-http.txt"
        bad_runtime
        bad_permissions
        ;;
    permissions)
        bad_permissions
        ;;
    reboot)
        [[ -r "$out/operator-config.sha256" ]]
        cat /proc/sys/kernel/random/boot_id >"$out/reboot-id"
        ! cmp --silent "$out/first-boot-id" "$out/reboot-id" || {
            echo 'Guest did not reboot' >&2
            exit 1
        }
        sha256sum --check "$out/operator-config.sha256" >"$out/reboot-preserved.txt"
        assert_ready operator-test
        save_state reboot
        http_control >"$out/reboot-http.txt"
        journalctl -b -u hestia.service --no-pager -o cat >"$out/reboot-journal.txt"
        ;;
    *) exit 2 ;;
esac
echo "PASS $mode"
