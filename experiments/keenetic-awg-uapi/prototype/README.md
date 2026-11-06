# Локальная сборка изолированного AWG runtime и probe

Исходник демона закреплён на официальном upstream `amneziawg-go` tag `v3.1.20260828`, commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`. Используется Go 1.27.3 и официальный target `generate-version-and-build`, который записывает версию тега в `version.go`. Для исследования демон отдельно собран со штатным linker override `ipc.socketDirectory`, который upstream предусмотрел для изменения каталога UAPI. Сборка остаётся ARM64 Linux static; в исходник демона функциональные патчи не внесены.

## Сборка демона

```sh
git clone --depth 1 --branch v3.1.20260828 https://github.com/amnezia-vpn/amneziawg-go.git amneziawg-go
git -C amneziawg-go rev-parse HEAD
cd amneziawg-go
make clean
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  GOFLAGS='-trimpath -buildvcs=false -ldflags=-X=github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory=/opt/tmp/hestia-awg-uapi-26b84f/runtime' \
  make generate-version-and-build
```

Сборка должна сообщить commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`, version `v3.1.20260828` и содержать строку каталога `/opt/tmp/hestia-awg-uapi-26b84f/runtime`. Для другого прогона поменяйте уникальную часть каталога и задайте то же значение в `-X` и аргументе `runtime-dir` probe. Сборка проверенного демона записана в [evidence](../evidence/local-build.txt); итоговый ARM64 ELF и SHA-256: [локальный артефакт](../../../dist/keenetic-awg-uapi/amneziawg-go-isolated).

## Сборка probe

Из корня репозитория:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -buildvcs=false \
  -o dist/keenetic-awg-uapi/awg-uapi-probe \
  experiments/keenetic-awg-uapi/prototype/probe.go
```

Probe использует только стандартную библиотеку Go. Он создаёт TUN с `TUNSETIFF(IFF_TUN|IFF_NO_PI|IFF_TUN_EXCL)`, создаёт Unix listener в каталоге, совпадающем с linker override, передаёт daemon fd 3 и 4 в `WG_TUN_FD`/`WG_UAPI_FD`, и запускает `-f`. Родительский listener не удаляет путь при закрытии; демон снимает свой сокет при штатном завершении. Дочерний процесс имеет 15-секундный `CommandContext`, нормальная очистка ограничена ожиданием 4 секунды и аварийным `SIGKILL`.

Probe записывает только коды UAPI, число peers, булевы итоги сравнения X25519 public derivation и флаги интерфейса. Содержимое ключа и сырой ответ `get` никогда не печатаются. Передача в устройство выполняется по SSH с `StrictHostKeyChecking=yes`, а SHA-256 проверяется удалённо до запуска.

Итоговый daemon SHA-256 `de208c103ee5295b22ee85b8745d7a8a80285165d8bdd62787e28d20545493a1`; probe SHA-256 `0846f4465fc8f5d523a3712621ebfcee3e67e8d98b7b9b4099fcdf6c03bedb5a`. Все команды и их фактические коды завершения записаны в [`local-build.txt`](../evidence/local-build.txt), [`local-verification.txt`](../evidence/local-verification.txt), [`device-transfer.txt`](../evidence/device-transfer.txt) и [`device-run.txt`](../evidence/device-run.txt).
