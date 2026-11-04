#!/usr/bin/env bash
# Run inside a disposable ARM64 VM. Inputs and results live in separate directories.
set -euo pipefail
umask 077
[[ $EUID == 0 && $# == 4 ]]
bundle=$(realpath "$1")
profile=$(realpath "$2")
mode=$3
out=$(realpath -m "$4")
[[ $mode == source || $mode == imported ]]
mkdir -p "$out"
[[ -z $(ls -A "$out") ]]
lab=$(cd "$(dirname "$0")" && pwd)
# run invokes the portable installer using the selected profile and its adjacent VPN files.
run() { (cd "$(dirname "$profile")" && bash "$bundle" --config "$profile"); }
ip -4 route show default >"$out/original-default-route"
find "$(dirname "$profile")" -maxdepth 1 -type f -printf '%f\n' | sort >"$out/input-names"
run >"$out/install.log" 2>&1
grep -q 'PASS:' "$out/install.log"
python3 "$lab/profile-test.py" "$profile" >"$out/runtime.txt"
ss -H -ltpn 'sport = :1080' | grep -q '127.0.0.1:1080'
ip -4 route show default | cmp - "$out/original-default-route"
sha256sum /etc/hestia/{snapshot,sing-box,profile}.json >"$out/pre-invalid.sha256"
# An intact running install must survive loss of a profile-relative peer file.
peer="$(dirname "$profile")/fi-wg.conf"
[[ -f $peer && ! -e $peer.hold ]]
mv -- "$peer" "$peer.hold"
trap 'mv -f -- "$peer.hold" "$peer"' EXIT
if run >"$out/missing-peer.log" 2>&1; then
    echo 'Missing peer config accepted' >&2
    exit 1
fi
mv -- "$peer.hold" "$peer"
trap - EXIT
sha256sum --check "$out/pre-invalid.sha256" >"$out/invalid-preserved.txt"
for u in hestia hestia-sing-box; do systemctl is-active --quiet "$u"; done
if [[ $mode == source ]]; then
    # Availability changes while both services are running. The export must include
    # the live snapshot and must not contain any key/value from the peer-file body.
    python3 - <<'PYHEALTH'
import json, os, pathlib, tempfile
path = pathlib.Path("/etc/hestia/snapshot.json")
cfg = json.loads(path.read_text())
cfg["healthy"] = {"ru-wg": True, "fi-wg": False}
st = path.stat()
with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
    os.fchown(f.fileno(), st.st_uid, st.st_gid)
    os.fchmod(f.fileno(), st.st_mode & 0o777)
    json.dump(cfg, f)
os.replace(f.name, path)
PYHEALTH
fi
for _ in {1..80}; do
    selected=$(curl --noproxy '*' -fsS http://127.0.0.1:9090/proxies/russia | python3 -c 'import json,sys;print(json.load(sys.stdin)["now"])')
    [[ $selected == ru-wg ]] && break
    sleep .1
done
[[ $selected == ru-wg ]]
/usr/local/bin/hestia-export-config "$out/export.json"
[[ $(stat -c %a "$out/export.json") == 600 ]]
python3 - "$profile" "$out/export.json" <<'PYEXPORT'
import json,sys
from pathlib import Path
profile, dest = map(Path, sys.argv[1:])
source, exported = (json.loads(p.read_text()) for p in (profile, dest))
source['healthy'] = {"ru-wg": True, "fi-wg": False}
assert exported == source
for interface in source["interfaces"]:
    wg = (profile.parent / interface["config_file"]).read_text()
    for line in wg.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() in {"privatekey","publickey","presharedkey"}:
            assert value.strip() not in dest.read_text()
for value in ("private_key", "peer_key", "PrivateKey", "PublicKey", "PresharedKey"):
    assert value not in dest.read_text()
print("PASS export matches file references, groups, domain lists and latest availability")
PYEXPORT
hash_before=$(sha256sum "$out/export.json")
if /usr/local/bin/hestia-export-config "$out/export.json" >"$out/overwrite.log" 2>&1; then exit 1; fi
[[ $(sha256sum "$out/export.json") == "$hash_before" ]]
python3 "$lab/profile-test.py" "$out/export.json" >"$out/runtime-after.txt"
sha256sum /etc/hestia/{snapshot,sing-box}.json >"$out/final-runtime.sha256"
echo "PASS $mode: profile install, invalid/missing external file, service availability, root-only export and no overwrite"
