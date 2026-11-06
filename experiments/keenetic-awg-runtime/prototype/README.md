# Статическая сборка awg-tools для ARM64

Проектный runtime из набора Hestia собран динамически под glibc и на KN-1012 требует `GLIBC_2.33` и `GLIBC_2.34`, которых нет в Entware glibc 2.27. Ни один официальный Linux ARM64/static binary в релизе upstream `v3.1.20260812` не найден: опубликованы Ubuntu 22.04 и Alpine 3.19 пакеты; upstream workflow запускает нативные сборки на `ubuntu-latest`, без ARM64 cross target. См. [протокол совместимости](../README.md#фактический-результат), [upstream release](https://github.com/amnezia-vpn/amneziawg-tools/releases/tag/v3.1.20260812) и [upstream workflow](https://github.com/amnezia-vpn/amneziawg-tools/blob/master/.github/workflows/linux-build.yml).

Проверенный локальный прототип собран из официального tag `v3.1.20260812`, commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`, Zig 0.17.1 для macOS ARM64. SHA архивов, команды сборки, тип ELF и хеш бинарника записаны в [build evidence](../evidence/static-build.txt). Готовый бинарник хранится вне Git: `dist/keenetic-awg-runtime/awg-musl-static-aarch64`, SHA-256 `a04ad65d551c6524f89d5939a39f382be7d1e5b48c0d833b1809480fc07adaf3`.

Для повторной сборки:

```sh
git clone --depth 1 --branch v3.1.20260812 https://github.com/amnezia-vpn/amneziawg-tools.git awg-tools
git -C awg-tools rev-parse HEAD
make -C awg-tools/src clean
env \
  ZIG_LOCAL_CACHE_DIR=/private/tmp/hestia-awg-zig-local-cache \
  ZIG_GLOBAL_CACHE_DIR=/private/tmp/hestia-awg-zig-global-cache \
  make -C awg-tools/src -j2 PLATFORM=linux \
  CC='/path/to/zig-0.17.1/zig cc -target aarch64-linux-musl' \
  LDFLAGS=-static V=1
file awg-tools/src/wg
shasum -a 256 awg-tools/src/wg
```

До сборки закрепите commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` и проверьте официальную SHA Zig 0.17.1 из `https://ziglang.org/download/index.json`. Сборка не устанавливает пакеты в систему.

На KN-1012 статический бинарник прошёл только `--version` и `--help`. Это не доказывает поддержку AWG daemon, UAPI, TUN, handshakes, туннельного трафика, маршрутизации, DNS или отказобезопасности.
