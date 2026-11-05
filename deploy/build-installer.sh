#!/usr/bin/env bash
# Build a two-file deployment: this archive plus the operator's JSON profile.
set -euo pipefail
[[ $# == 3 ]] || {
    echo "Usage: $0 linux-arm64-controller sing-box.tar.gz output.run" >&2
    exit 2
}
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export COPYFILE_DISABLE=1
mkdir -p "$work/app/deploy/bootstrap" "$work/app/deploy/systemd/hestia.service.d"
for name in install.sh sing-box-1.14.4-linux-arm64.sha256 profile.py smoke.py export-config.py bootstrap/snapshot.json bootstrap/sing-box.json systemd/hestia.service systemd/hestia-smoke@.service systemd/hestia-binding-recovery.service systemd/hestia-binding-watch.path systemd/hestia-binding-watch.service systemd/hestia-binding.conf systemd/hestia-observe.service systemd/hestia-dns.service systemd/hestia-sing-box.service systemd/hestia.service.d/backend.conf; do
    cp "$repo/deploy/$name" "$work/app/deploy/$name"
done
mkdir -p "$work/app/backend/internal/geoip"
cp "$repo/backend/internal/geoip/countries.txt" "$work/app/backend/internal/geoip/"
mkdir -p "$work/app/deploy/systemd"
cp "$repo/deploy/systemd/"hestia-geoip-publish.{service,timer} "$work/app/deploy/systemd/"
cp -R "$repo/deploy/geoip" "$work/app/deploy/"
cp "$repo/deploy/"{geoip-install.sh,import_geoip.py,publish_geoip.py} "$work/app/deploy/"
cp "$1" "$work/app/controller"
if ! GOENV=off GOTOOLCHAIN=local go version -m "$work/app/controller" | awk '
    $1 == "build" && $2 == "GOOS=linux" { linux = 1 }
    $1 == "build" && $2 == "GOARCH=arm64" { arm64 = 1 }
    END { exit !(linux && arm64) }
'; then
    echo "Controller must be a Go executable built for linux/arm64" >&2
    exit 1
fi
cp "$2" "$work/app/sing.tgz"
(cd "$work/app" && shasum -a 256 -c "deploy/sing-box-1.14.4-linux-arm64.sha256")
mv "$work/app/sing.tgz" "$work/app/sing-box.tgz"
tar -czf "$work/archive" -C "$work/app" deploy backend controller sing-box.tgz
digest=$(shasum -a 256 "$work/archive" | cut -d' ' -f1)
cat >"$work/output" <<'HEADER'
#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# == 0 || ( $# == 2 && $1 == --config ) ]] || { echo "Usage: sudo bash hestia-arm64.run [--config FILE]" >&2; exit 2; }
[[ $EUID == 0 ]] || { echo "Run as root" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
line=$(awk '/^__HESTIA_PAYLOAD__$/ {print NR+1; exit}' "$0")
tail -n +"$line" "$0" > "$work/payload"
HEADER
{
    # Expand $work when running the generated installer, not while writing it.
    # shellcheck disable=SC2016
    printf 'echo "%s  $work/payload" | sha256sum -c -\n' "$digest"
    cat <<'HEADER'
tar -xzf "$work/payload" -C "$work"
bash "$work/deploy/install.sh" --controller-binary "$work/controller" --sing-box-archive "$work/sing-box.tgz" "$@"
exit 0
__HESTIA_PAYLOAD__
HEADER
    cat "$work/archive"
} >>"$work/output"
install -m 0755 "$work/output" "$3"
