#!/usr/bin/env bash
# Internal entry point called by host.sh in its isolated Debian ARM64 guest.
set -euo pipefail
[[ $# == 2 && $EUID == 0 && $(dpkg --print-architecture) == arm64 ]]
mode=$1
bundle=$2
app=/opt/hestia-scheme3-app
panel=/etc/systemd/system/hestia-panel.service
panel_sudoers=/etc/sudoers.d/hestia-panel
awg_tmpfiles=/etc/tmpfiles.d/hestia-awg.conf
binding_tmpfiles=/etc/tmpfiles.d/hestia-binding.conf
binding_recovery=/etc/systemd/system/hestia-binding-recovery.service
binding_watch_path=/etc/systemd/system/hestia-binding-watch.path
binding_watch_service=/etc/systemd/system/hestia-binding-watch.service
awg_service=/etc/systemd/system/hestia-awg.service
awg_tools=/usr/local/bin/awg
awg_go=/usr/local/lib/hestia/amneziawg-go
awg_store=/etc/hestia/awg
awg_version_marker=/etc/hestia/.awg-runtime-version
profile_link=/usr/local/lib/hestia/profile.py
marker=$app/.managed
awg_go_version=3.1.20260828
awg_tools_version=3.1.20260812
app_created=0
sing_box_created=0
release=
panel_user_created=0
panel_group_created=0
snapshot_group_created=0
snapshot_metadata_before=
sing_box_metadata_before=
profile_adoption_created=0
managed_marker_before=0
panel_sudoers_created=0
awg_tmpfiles_created=0
binding_tmpfiles_created=0
binding_recovery_created=0
binding_watch_path_created=0
binding_watch_service_created=0
awg_service_created=0
binding_path_enabled_before=0
binding_path_active_before=0
awg_store_created=0
awg_go_created=0
awg_tools_created=0
awg_version_marker_created=0
profile_link_created=0
gateway_ip=$(ip -4 -o addr show dev lima0 scope global | awk '{print $4}')
gateway_ip=${gateway_ip%/*}
[[ $gateway_ip =~ ^192\.168\.1\.[0-9]+$ && $gateway_ip != 192.168.1.133 && $(hostname -s) != lima-hestia-stage1 ]] ||
    {
        echo "Expected a separate isolated VM on the scheme 3 LAN" >&2
        exit 1
    }

if [[ $mode == install && ! -f $marker ]]; then
    for path in "$app" "$panel" "$panel_sudoers" "$awg_tmpfiles" "$binding_tmpfiles" "$binding_recovery" "$binding_watch_path" "$binding_watch_service" "$awg_service" "$awg_store" "$awg_tools" "$awg_go" "$awg_version_marker" "$profile_link" \
        /usr/local/bin/{hestia,sing-box} /etc/{hestia,wireguard/wg-keenetic.conf} /etc/systemd/system/{hestia,hestia-sing-box}.service; do
        [[ ! -e $path && ! -L $path ]] || {
            echo "Unmanaged path: $path" >&2
            exit 1
        }
    done
    ! getent passwd hestia-panel >/dev/null || {
        echo "Unmanaged account: hestia-panel" >&2
        exit 1
    }
    ! getent group hestia-panel >/dev/null || {
        echo "Unmanaged group: hestia-panel" >&2
        exit 1
    }
    app_created=1
    install -d -m 0755 "$app"
    touch "$marker"
fi
[[ -f $marker && ($mode == install || $mode == update) ]]
exec 9>"$app/.lock"
flock -n 9
if [[ -f /etc/hestia/snapshot.json && ! -L /etc/hestia/snapshot.json ]]; then
    snapshot_metadata_before=$(stat -c '%u:%g:%a' /etc/hestia/snapshot.json)
fi
if [[ -f /etc/hestia/sing-box.json && ! -L /etc/hestia/sing-box.json ]]; then
    sing_box_metadata_before=$(stat -c '%u:%g:%a' /etc/hestia/sing-box.json)
fi
if [[ -e /etc/hestia/.installer-managed || -L /etc/hestia/.installer-managed ]]; then
    managed_marker_before=1
fi
if [[ $mode == update ]]; then
    [[ $(systemctl is-enabled hestia-binding-watch.path 2>/dev/null || :) == enabled ]] && binding_path_enabled_before=1
    [[ $(systemctl is-active hestia-binding-watch.path 2>/dev/null || :) == active ]] && binding_path_active_before=1
    command -v python3 >/dev/null || {
        echo "Python 3 is required to verify the managed profile" >&2
        exit 1
    }
    python3 -I "$bundle/scheme3/adopt-profile.py" check /etc/hestia "$bundle/scheme3/guest-profile.json" "$bundle/scheme3/profile.py"
fi

# rollback_preflight receives the current exit status; on early failure it removes only fresh app/release/sing-box paths and returns that status.
rollback_preflight() {
    local status=$?
    if ((status != 0)); then
        set +e
        [[ -z $release ]] || rm -rf -- "$release"
        ((sing_box_created == 0)) || rm -f -- /usr/local/bin/sing-box
        if ((app_created)); then
            rm -f -- /usr/local/bin/hestia
            rm -rf -- "$app"
        fi
    fi
    exit "$status"
}
trap rollback_preflight EXIT

# protected_directory accepts an existing system directory only when root owns it and non-root users cannot write it.
protected_directory() {
    local directory=$1 mode
    [[ ! -e $directory && ! -L $directory ]] && return 0
    [[ -d $directory && ! -L $directory && $(stat -c '%u' "$directory") == 0 ]] || {
        echo "Unsafe system directory: $directory" >&2
        return 1
    }
    mode=$(stat -c '%a' "$directory")
    (((8#$mode & 022) == 0)) || {
        echo "System directory is writable by non-root: $directory" >&2
        return 1
    }
}

protected_directory /etc/hestia
protected_directory /usr/local/bin
protected_directory /usr/local/lib
protected_directory /usr/local/lib/hestia

if [[ $mode == install ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables curl tcpdump ca-certificates sudo build-essential python3
    install -m 0755 "$bundle/sing-box" /usr/local/bin/sing-box.next
    mv -fT /usr/local/bin/sing-box.next /usr/local/bin/sing-box
    sing_box_created=1
elif ! command -v sudo >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sudo
fi

release=$(mktemp -d "$app/release.XXXXXXXX")
chmod 0755 "$release"
(cd "$bundle" && sha256sum --check awg-SHA256SUMS)
install -m 0755 "$bundle/hestia" "$bundle/hestia-panel" "$release/"
"$bundle/amneziawg-go" --version | grep -F "amneziawg-go v$awg_go_version" >/dev/null || {
    echo "Bundled amneziawg-go version does not match the pinned release" >&2
    exit 1
}
cp -R "$bundle/browser" "$release/browser"
chmod -R u=rwX,go=rX "$release/browser"
install -o root -g root -m 0644 "$bundle/scheme3/profile.py" "$release/profile.py"
old=$(readlink "$app/current" || :)
if [[ -f $panel ]]; then cp -p -- "$panel" "$release/previous-panel.service"; fi
# switch_release accepts an existing release path and atomically publishes it through the `current` symlink; filesystem errors propagate.
switch_release() {
    ln -sfn "$1" "$app/current.next"
    mv -fT "$app/current.next" "$app/current"
}
# rollback restores the old application/unit and removes only AWG/group files created by this invocation; it returns the original failure status.
rollback() {
    local status=$?
    if ((status != 0)); then
        set +e
        systemctl stop hestia-panel >/dev/null 2>&1
        if ((app_created || binding_recovery_created)); then systemctl stop hestia-binding-recovery.service >/dev/null 2>&1; fi
        if ((binding_path_enabled_before == 0)); then systemctl disable hestia-binding-watch.path >/dev/null 2>&1 || :; fi
        if ((awg_tmpfiles_created)); then systemd-tmpfiles --remove "$awg_tmpfiles" >/dev/null 2>&1 || :; fi
        if ((binding_tmpfiles_created)); then systemd-tmpfiles --remove "$binding_tmpfiles" >/dev/null 2>&1 || :; fi
        if [[ -n $old ]]; then
            switch_release "$old"
            if [[ -f $release/previous-panel.service ]]; then cp -p -- "$release/previous-panel.service" "$panel"; fi
        else
            rm -f -- "$panel"
        fi
        if [[ -n $snapshot_metadata_before && -f /etc/hestia/snapshot.json ]]; then
            IFS=: read -r snapshot_uid snapshot_gid snapshot_mode <<<"$snapshot_metadata_before"
            chown "$snapshot_uid:$snapshot_gid" /etc/hestia/snapshot.json
            chmod "$snapshot_mode" /etc/hestia/snapshot.json
        fi
        if ((profile_adoption_created)); then
            python3 -I "$bundle/scheme3/adopt-profile.py" rollback /etc/hestia "$bundle/scheme3/guest-profile.json" "$release/profile.py" >/dev/null 2>&1 || :
        fi
        if [[ -n $sing_box_metadata_before && -f /etc/hestia/sing-box.json ]]; then
            IFS=: read -r sing_box_uid sing_box_gid sing_box_mode <<<"$sing_box_metadata_before"
            chown "$sing_box_uid:$sing_box_gid" /etc/hestia/sing-box.json
            chmod "$sing_box_mode" /etc/hestia/sing-box.json
        fi
        ((panel_sudoers_created == 0)) || rm -f -- "$panel_sudoers"
        ((awg_tmpfiles_created == 0)) || rm -f -- "$awg_tmpfiles"
        ((binding_recovery_created == 0)) || rm -f -- "$binding_recovery"
        ((binding_watch_path_created == 0)) || rm -f -- "$binding_watch_path"
        ((binding_watch_service_created == 0)) || rm -f -- "$binding_watch_service"
        ((awg_service_created == 0)) || rm -f -- "$awg_service"
        ((binding_tmpfiles_created == 0)) || rm -f -- "$binding_tmpfiles"
        ((awg_go_created == 0)) || rm -f -- "$awg_go"
        ((awg_tools_created == 0)) || rm -f -- "$awg_tools"
        ((awg_version_marker_created == 0)) || rm -f -- "$awg_version_marker"
        ((profile_link_created == 0)) || rm -f -- "$profile_link"
        if ((awg_store_created)); then rmdir "$awg_store" >/dev/null 2>&1 || :; fi
        ((sing_box_created == 0)) || rm -f -- /usr/local/bin/sing-box
        if ((panel_user_created)); then userdel hestia-panel >/dev/null 2>&1 || :; fi
        if ((panel_group_created)); then groupdel hestia-panel >/dev/null 2>&1 || :; fi
        if ((snapshot_group_created)); then
            if [[ -f /etc/hestia/snapshot.json ]]; then
                chown root:root /etc/hestia/snapshot.json
                chmod 0644 /etc/hestia/snapshot.json
            fi
            if [[ -e /run/hestia-install.lock ]]; then
                chown root:root /run/hestia-install.lock
                chmod 0600 /run/hestia-install.lock
            fi
            groupdel hestia-snapshot >/dev/null 2>&1 || :
        fi
        systemctl daemon-reload >/dev/null 2>&1
        if ((binding_path_active_before == 0)); then systemctl stop hestia-binding-watch.path >/dev/null 2>&1 || :; fi
        if ((app_created)); then
            rm -f -- /usr/local/bin/hestia
            rm -rf -- "$app"
        fi
        if [[ -n $old ]]; then
            systemctl restart hestia hestia-panel >/dev/null 2>&1 || :
        fi
    fi
    if ((status != 0)); then rm -rf -- "$release"; fi
    exit "$status"
}
if [[ $mode == update ]]; then
    [[ -n $old && $(readlink /usr/local/bin/hestia) == "$app/current/hestia" ]]
    "$release/hestia" -check -config /etc/hestia/snapshot.json
fi
trap rollback EXIT

# panel_account accepts no input; it validates or creates the fixed unprivileged panel user/group and fails on conflicting identity state.
panel_account() {
    if getent passwd hestia-panel >/dev/null; then
        [[ $(getent group hestia-panel | cut -d: -f1) == hestia-panel &&
        $(getent passwd hestia-panel | cut -d: -f7) == /usr/sbin/nologin ]] || {
            echo "Existing hestia-panel account is not the managed service identity" >&2
            return 1
        }
        return 0
    fi
    if getent group hestia-panel >/dev/null; then
        echo "Unmanaged group hestia-panel already exists" >&2
        return 1
    fi
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin hestia-panel
    panel_user_created=1
    panel_group_created=1
}

# snapshot_group accepts no input; it creates the snapshot read group only when absent and records creation for rollback.
snapshot_group() {
    if ! getent group hestia-snapshot >/dev/null; then
        groupadd --system hestia-snapshot
        snapshot_group_created=1
    fi
}

# managed_file accepts a source, destination and mode; it installs a root-owned file or accepts an identical managed file, rejecting conflicts.
managed_file() {
    local source=$1 target=$2 mode=$3
    if [[ -e $target || -L $target ]]; then
        [[ -f $target && ! -L $target && $(stat -c '%u:%g:%a' "$target") == "0:0:${mode#0}" ]] || {
            echo "Unsafe managed file: $target" >&2
            return 1
        }
        cmp -s "$source" "$target" || {
            echo "Managed file differs from the package: $target" >&2
            return 1
        }
        return 0
    fi
    install -o root -g root -m "$mode" "$source" "$target"
    case $target in
        "$panel_sudoers") panel_sudoers_created=1 ;;
        "$awg_tmpfiles") awg_tmpfiles_created=1 ;;
        "$binding_tmpfiles") binding_tmpfiles_created=1 ;;
        "$binding_recovery") binding_recovery_created=1 ;;
        "$binding_watch_path") binding_watch_path_created=1 ;;
        "$binding_watch_service") binding_watch_service_created=1 ;;
        "$awg_service") awg_service_created=1 ;;
    esac
}

# prepare_awg_tools accepts a private build directory, verifies or installs pinned runtime/tools, and fails on version, build or ownership mismatch.
prepare_awg_tools() {
    local source=$1
    if [[ -x $awg_tools ]]; then
        [[ -x $awg_go && -f $awg_version_marker && $(cat "$awg_version_marker") == "amneziawg-go=$awg_go_version amneziawg-tools=$awg_tools_version" ]] || {
            echo "Existing AmneziaWG binaries lack the expected Hestia version marker" >&2
            return 1
        }
        "$awg_tools" --version | grep -F "v$awg_tools_version" >/dev/null || {
            echo "Installed awg version does not match the pinned release" >&2
            return 1
        }
        "$awg_go" --version | grep -F "amneziawg-go v$awg_go_version" >/dev/null || {
            echo "Installed amneziawg-go version does not match the pinned release" >&2
            return 1
        }
        return 0
    fi
    [[ ! -e $awg_tools && ! -L $awg_tools ]] || {
        echo "Unsafe AmneziaWG tools path" >&2
        return 1
    }
    [[ ! -e $awg_go && ! -L $awg_go && ! -e $awg_version_marker && ! -L $awg_version_marker ]] || {
        echo "Cannot safely migrate partial AmneziaWG runtime installation" >&2
        return 1
    }
    if ! command -v make >/dev/null || ! command -v gcc >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential
    fi
    mkdir -m 0700 "$source"
    tar -xf "$bundle/amneziawg-tools-source.tar" -C "$source"
    make -C "$source/src"
    "$source/src/wg" --version | grep -F "v$awg_tools_version" >/dev/null || {
        echo "Built awg version does not match the pinned release" >&2
        return 1
    }
    install -d -m 0755 /usr/local/bin /usr/local/lib/hestia
    install -m 0755 "$bundle/amneziawg-go" "$awg_go"
    awg_go_created=1
    install -m 0755 "$source/src/wg" "$awg_tools"
    awg_tools_created=1
    printf 'amneziawg-go=%s amneziawg-tools=%s\n' "$awg_go_version" "$awg_tools_version" >"$release/awg-runtime-version"
    install -o root -g root -m 0600 "$release/awg-runtime-version" "$awg_version_marker"
    awg_version_marker_created=1
}

panel_account
snapshot_group
[[ -d /etc/hestia && ! -L /etc/hestia ]] || {
    echo "Hestia configuration directory is unavailable" >&2
    exit 1
}
if [[ -e $awg_store || -L $awg_store ]]; then
    [[ -d $awg_store && ! -L $awg_store && $(stat -c '%u:%a' "$awg_store") == 0:700 ]] || {
        echo "Unsafe AmneziaWG profile store" >&2
        exit 1
    }
else
    install -d -o root -g root -m 0700 "$awg_store"
    awg_store_created=1
fi
prepare_awg_tools "$release/awg-tools-build"
install -d -m 0700 "$release/awg-check-config"
visudo -cf "$bundle/scheme3/hestia-panel.sudoers" >/dev/null
managed_file "$bundle/scheme3/hestia-panel.sudoers" "$panel_sudoers" 0440
managed_file "$bundle/scheme3/hestia-awg.tmpfiles" "$awg_tmpfiles" 0644
managed_file "$bundle/scheme3/hestia-binding.conf" "$binding_tmpfiles" 0644
managed_file "$bundle/scheme3/hestia-binding-recovery.service" "$binding_recovery" 0644
managed_file "$bundle/scheme3/hestia-binding-watch.path" "$binding_watch_path" 0644
managed_file "$bundle/scheme3/hestia-binding-watch.service" "$binding_watch_service" 0644
managed_file "$bundle/scheme3/hestia-awg.service" "$awg_service" 0644
systemd-tmpfiles --create "$binding_tmpfiles" "$awg_tmpfiles"
snapshot_gid=$(getent group hestia-snapshot | cut -d: -f3)
[[ -n $snapshot_gid && $(stat -c '%u:%g:%a' /run/hestia-install.lock) == "0:${snapshot_gid}:640" ]] || {
    echo "Unsafe Hestia binding lock permissions" >&2
    exit 1
}
install -d -o root -g hestia-snapshot -m 0750 /run/hestia-awg
switch_release "$release"
ln -sfn "$app/current/hestia" /usr/local/bin/hestia
if [[ -e $profile_link || -L $profile_link ]]; then
    [[ -L $profile_link && $(readlink "$profile_link") == "$app/current/profile.py" ]] || {
        echo "Conflicting managed profile compiler path: $profile_link" >&2
        exit 1
    }
else
    ln -s "$app/current/profile.py" "$profile_link"
    profile_link_created=1
fi
if [[ $mode == install ]]; then
    if ((managed_marker_before == 0)); then profile_adoption_created=1; fi
    bash "$bundle/scheme3/guest-bootstrap.sh"
fi
python3 -I "$bundle/scheme3/adopt-profile.py" adopt /etc/hestia "$bundle/scheme3/guest-profile.json" "$profile_link"
if ((managed_marker_before == 0)); then profile_adoption_created=1; fi
chown root:root /etc/hestia/sing-box.json
chmod 0600 /etc/hestia/sing-box.json
chown root:hestia-snapshot /etc/hestia/snapshot.json
chmod 0640 /etc/hestia/snapshot.json
systemctl enable --now hestia-binding-watch.path
sed "s/@LAN_IP@/$gateway_ip/" "$bundle/scheme3/host-panel.service.in" >"$panel"
systemctl daemon-reload
systemctl enable hestia-panel
systemctl restart hestia hestia-panel
curl --noproxy '*' -fsS --retry 5 --retry-delay 1 --retry-connrefused "http://$gateway_ip:8080/api/groups-and-rules" >/dev/null
for service in hestia hestia-panel hestia-sing-box; do systemctl is-active "$service"; done
printf 'Panel: http://%s:8080\n' "$gateway_ip"
