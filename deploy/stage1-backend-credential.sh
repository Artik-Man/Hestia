#!/usr/bin/env bash
# Source this helper from a stage1 installer before validating or installing the backend credential drop-in.
backend_unit=/etc/systemd/system/hestia-sing-box.service
backend_dropin_dir=${backend_unit}.d
backend_dropin=$backend_dropin_dir/80-hestia-backend-credential.conf
migrate_backend=0

# check_backend_credential accepts a known root-owned stage1 fragment and an absent or identical protected drop-in.
check_backend_credential() {
    local source=$1 unit_hash
    [[ -f $backend_unit && ! -L $backend_unit && $(stat -c '%u:%g:%a' "$backend_unit") == 0:0:644 &&
    $(systemctl show hestia-sing-box.service -p FragmentPath --value) == "$backend_unit" ]] || return 1
    if [[ -e $backend_dropin_dir || -L $backend_dropin_dir ]]; then
        [[ -d $backend_dropin_dir && ! -L $backend_dropin_dir && $(stat -c '%u:%g:%a' "$backend_dropin_dir") == 0:0:755 ]] || return 1
    fi
    if [[ -e $backend_dropin || -L $backend_dropin ]]; then
        [[ -f $backend_dropin && ! -L $backend_dropin && $(stat -c '%u:%g:%a' "$backend_dropin") == 0:0:644 ]] && cmp -s "$source" "$backend_dropin" || return 1
    fi
    unit_hash=$(sha256sum "$backend_unit" | cut -d' ' -f1)
    case $unit_hash in
        0e997b7c0163ca32c36291d9cef3e7c49f00ad0732b6396f0c2a95a47ff7b871 | 6e9cc0d31c09b8fac8c7cf4e0932608068d905cacf0b999f0c993639cb69c54c)
            if [[ ! -f $backend_dropin ]]; then migrate_backend=1; fi
            ;;
        *)
            grep -Fxq 'LoadCredential=sing-box.json:/etc/hestia/sing-box.json' "$backend_unit" &&
                grep -Eq '^ExecStart=/usr/local/(bin|lib/hestia)/sing-box run -c %d/sing-box\.json$' "$backend_unit" || return 1
            ;;
    esac
}

# install_backend_credential adds the validated drop-in without changing the backend unit's network hooks.
install_backend_credential() {
    if ((migrate_backend)); then
        install -d -o root -g root -m 0755 "$backend_dropin_dir"
        install -o root -g root -m 0644 "$1" "$backend_dropin"
    fi
}
