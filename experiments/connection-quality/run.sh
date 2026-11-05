#!/usr/bin/env bash
# Run inside a private mount/PID/network namespace on the explicitly selected ARM64 lab VM.
set -euo pipefail
[[ $(hostname) == lima-hestia-load-01 && $$ == 1 && $(id -u) == 0 ]]
[[ $(ip -o link show | wc -l) -eq 1 && -z $(ip route show default) ]]
mount --make-rprivate /
mount -t sysfs -o ro sysfs /sys
mount --bind "$PWD" /mnt
cd /mnt
chmod 0755 .
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /var/lib
mkdir -p /run/hestia-quality /var/lib/hestia-quality-settings
chown 65534:65534 /run/hestia-quality
chown 65533:65533 /var/lib/hestia-quality-settings
ip link set lo up
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=quality.test' -addext 'subjectAltName=DNS:quality.test' -keyout key.pem -out cert.pem 2>cert.log
export SSL_CERT_FILE="$PWD/cert.pem"
for path in one two; do
    index=1
    [[ $path == two ]] && index=2
    mkdir -p "$path"
    ip netns add "$path"
    ip link add "$path" type veth peer name dest netns "$path"
    ip addr add "10.0.$index.1/30" dev "$path"
    ip link set "$path" up
    ip netns exec "$path" ip link set lo up
    ip netns exec "$path" ip addr add "10.0.$index.2/30" dev dest
    ip netns exec "$path" ip link set dest up
    for target in 1.1.1.1 8.8.8.8; do
        ip netns exec "$path" ip addr add "$target/32" dev lo
        ip route add "$target/32" dev "$path" via "10.0.$index.2" metric "$index"
    done
    (cd "$path" && exec ip netns exec "$path" python3 ../respond.py) &
    (cd "$path" && exec ip netns exec "$path" ../quality-test-service) &
done
cat >profile.json <<'JSON'
{"version":2,"interfaces":[{"id":"one","type":"direct","bind_interface":"one"},{"id":"two","type":"direct","bind_interface":"two"}],"groups":[{"id":"finland","exits":["one","two"],"defaultExit":"one"},{"id":"empty","exits":[],"defaultExit":"deny"}],"connectors":[],"inbounds":[],"lists":[],"healthy":{"one":true,"two":true}}
JSON
mkdir -p compiled assets
echo 'quality lab' >assets/index.html
python3 profile.py profile.json compiled .
chmod 0644 compiled/snapshot.json
python3 profile.py --quality-paths compiled/sing-box.json /run/hestia-quality
./sing-box run -c compiled/sing-box.json >backend.log 2>&1 &
setpriv --reuid=65533 --regid=65533 --clear-groups ./hestia-panel -assets assets -listen 127.0.0.1:8080 -snapshot "$PWD/compiled/snapshot.json" -quality-settings /var/lib/hestia-quality-settings/settings.json -quality-report /run/hestia-quality/report.json >panel.log 2>&1 &
for _ in {1..40}; do
    curl -fsS http://127.0.0.1:8080/api/quality -o initial.json 2>/dev/null && break
    sleep .25
done
python3 - <<'PY'
import json
report = json.load(open("initial.json"))
assert len(report["groups"]) == 2
settings = report["settings"]
for check in settings["checks"]:
    check.update(intervalSeconds=1, timeoutSeconds=1)
json.dump(settings,open("settings.json","w"))
PY
curl -fsS -X PUT -H 'Content-Type: application/json' --data-binary @settings.json http://127.0.0.1:8080/api/quality/settings >/dev/null
setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=+net_raw --ambient-caps=+net_raw ./hestia -watch -quality -config compiled/snapshot.json -interval 200ms >events.jsonl 2>worker.log &
python3 verify.py
