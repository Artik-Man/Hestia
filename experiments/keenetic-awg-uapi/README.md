# Изолированный userspace AmneziaWG и private UAPI на Keenetic Giga KN-1012

## Вопрос и результат

Можно ли на физическом KN-1012 запустить закреплённый `amneziawg-go` с собственным непостоянным TUN и private UAPI, прочитать и изменить только синтетическое состояние, а затем удалить все ресурсы опыта? **Да, для описанного ограниченного сценария.** Итоговый прогон завершился кодом 0: UAPI set/get вернули `errno=0`, число peers осталось 0, синтетический X25519 public derivation совпал до/после канонизации ключа, интерфейс всё время оставался административно DOWN, а процесс, TUN, сокет, временный каталог и staging-артефакты удалены.

Это подтверждает только запуск конкретного статического прототипа, готовность его private UAPI, синтетическую настройку ключа и очистку. Handshake, VPN, отправка пакетов, внешнее UDP-соединение, полный маршрут трафика и производительность не проверялись.

## Устройство и артефакты

- Устройство: физический Keenetic Giga KN-1012; SSH fingerprint `[192.168.1.1]:222` — ED25519 `SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo`; hostname `Keenetic-G-8919`; ядро `4.9-ndm-5`; архитектура `aarch64`.
- Сборка upstream: tag `v3.1.20260828`, commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`, Go `1.27.3`, `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`, upstream target `generate-version-and-build`, итоговая версия из `--version`: `v3.1.20260828`.
- Исследовательский демон использует upstream linker override `-X github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory=/opt/tmp/hestia-awg-uapi-26b84f/runtime`. SHA-256: `de208c103ee5295b22ee85b8745d7a8a80285165d8bdd62787e28d20545493a1`.
- Wrapper SHA-256: `0846f4465fc8f5d523a3712621ebfcee3e67e8d98b7b9b4099fcdf6c03bedb5a`.
- Исходник probe и команды воспроизведения находятся в [prototype](prototype/README.md); локальные скомпилированные файлы вне Git: `dist/keenetic-awg-uapi/`.
- Проверены `gofmt`, `go vet` для wrapper и pinned daemon и статическая ARM64 сборка; тесты приложения не добавлялись и не запускались.

## Основание из исходников и изоляция

В pinned `main.go` daemon принимает заранее открытые fd через `WG_TUN_FD` и `WG_UAPI_FD`, а `-f` удерживает процесс на переднем плане. Linux UAPI transport принимает уже открытый файл, но всё равно наблюдает путь `socketDirectory/interface.sock`; `ipc.socketDirectory` объявлен переменной, которую upstream разрешает менять linker flag. Поэтому preopened UAPI fd сам по себе не изолирует файловый эффект. Исследовательская сборка указывает `socketDirectory` на отдельный временный каталог и не создаёт `/var/run/amneziawg`. См. [main.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/main.go#L106-L126), [uapi_unix.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/ipc/uapi_unix.go#L25-L62) и [uapi_linux.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/ipc/uapi_linux.go#L50-L85).

Probe создаёт имя `hawg26b84f` только с `IFF_TUN|IFF_NO_PI|IFF_TUN_EXCL`, до запуска проверяет отсутствие имени и private runtime path. Затем создаёт сокет `/opt/tmp/hestia-awg-uapi-26b84f/runtime/hawg26b84f.sock`, передаёт daemon принадлежащие ему файловые дескрипторы и ограничивает процесс 15 секундами. Сетевых пространств имён нет и они не требуются этой файловой изоляции. До и после снимались IPv4/IPv6 routes и rules. Не задавались адреса, `IFF_UP`, peers, `listen_port`, `fwmark`, маршруты, firewall или постоянные настройки.

UAPI `set` передал только случайно сгенерированный эфемерный `private_key`; профиль и существующий ключ не читались. Закреплённый код нормализует входной private scalar при разборе (`FromMaybeZeroHex` вызывает `clamp`), поэтому сырые байты get/readback закономерно могут различаться. Проверка сравнивает только X25519 public derivation из исходного случайного значения и возвращённого канонического значения; сами ключи не попадают в журнал. `IpcGetOperation` не отдаёт отдельное поле device public key, поэтому опыт не утверждает независимую проверку публичного ключа, который сообщил бы daemon. В коде pinned UAPI только `listen_port` вызывает `BindUpdate`; выбранная операция задаёт только `private_key` и не открывает UDP listener. См. [device/uapi.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/uapi.go#L287-L321) и [noise-types.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/noise-types.go#L55-L70).

## Фактический результат финального прогона

Команда на устройстве:

```sh
./awg-uapi-probe /opt/tmp/hestia-awg-uapi-26b84f/runtime hawg26b84f ./amneziawg-go-isolated
```

Ограничение daemon lifetime в wrapper — 15 секунд. Финальный запуск завершился менее чем за секунду с SSH/remote code 0. Флаги интерфейса до daemon, во время его работы и после UAPI были `0x1090`; бит `IFF_UP` сброшен. Private UAPI socket был готов; `set` и `get` завершились с `errno=0`; `peers=0`; `returned_key_nonzero=true`; `synthetic_public_derivation_match=true`; daemon завершился с кодом 0.

После завершения интерфейс отсутствовал, сокет удалён daemon, private runtime directory удалён wrapper. Позднее удалены файлы опыта и пустой staging directory. Отдельная проверка подтвердила отсутствие TUN, staging directory и `/var/run/amneziawg`. Журнал подтверждает итоговое отсутствие, но точные имена временных macOS tar sidecar файлов и аргументы их удаления в raw evidence не сохранены. SHA256 четырёх таблиц IPv4/IPv6 routes/rules совпал до и после: `1e518b4651d62f4d2b47295287c7a803c65d7c13940674d6eb94250acc239a54`, `94483fe3d20363e24303b9e008af0aba262bb383a265f3bed9e0f0cb4a8530ba`, `52a656ed73f1a2c72f79a91fcd6f7cbe5bc59a1b33d5a89fb4e64cfac61c5b9c`, `77570d3b73b6f8265509d05ee2d03df846fd2f2d9f537a0dc58e0cb0739b1aaf`.

## Неудачные попытки и границы вывода

Все попытки и коды сохранены в raw журналах. Первый запуск команды через BusyBox `timeout` не начался: на устройстве отсутствует applet `timeout`; заменён ограничением `exec.CommandContext` в wrapper. Ещё одна попытка обнаружила ошибку wrapper: закрытие родного Unix listener удаляло pathname до того, как daemon поставит inotify watch. Она устранена `SetUnlinkOnClose(false)`; собственные socket-file и каталог удалялись при каждом выходе. Затем первая проверка ключа сравнила сырые значения до/после UAPI и ошибочно отклонила ожидаемую upstream канонизацию; обновлена проверка public derivation. Финальный прогон после исправлений прошёл. Снимки и хеши прежних версий wrapper сохранены в [revisions](evidence/revisions/).

Не проверялись пересылка пакетов через TUN, handshake, AmneziaWG obfuscation, внешние endpoint/UDP-сокеты, передача трафика, работа при конкурирующих сессиях, длительный запуск, производительность и надёжность восстановления. Успех не означает готовность production runtime или разрешение на изменение рабочих VPN и маршрутизации.

## Свидетельства

- [локальная сборка и исходные хеши](evidence/local-build.txt)
- [форматирование, vet, ELF и linker override](evidence/local-verification.txt)
- [read-only инвентаризация, host key и baseline маршрутизации](evidence/device-preflight.txt)
- [передача, SHA-256 и версия daemon](evidence/device-transfer.txt)
- [все фактические прогоны с выводом и кодами завершения](evidence/device-run.txt)
- [очистка staging и итоговая проверка](evidence/cleanup-verification.txt)
- [сохранённые и явно помеченные реконструированные исходники предыдущих wrapper revision](evidence/revisions/)

[Независимая сверка свидетельств](evidence/validation.txt) подтвердила финальный хеш probe при повторной локальной сборке, хеш демона и соответствие сохранённого прогона заявленному ограниченному результату. Проверяющий не обращался к устройству; пробел записи точной команды удаления служебных файлов сохранён как ограничение.
