# Протокол прогона sing-box loopback

Дата: 6 ноября 2026 года. Устройство: ранее подтверждённый Keenetic KN-1012, ARM64, KeeneticOS 5.2 Beta 2, ядро `4.9-ndm-5`. Выполнение производилось в отдельном каталоге `/opt/tmp/hestia-singbox-loopback.20261106-2045`, удалённом после завершения. ВМ не использовались.

## Runtime

- Официальный источник: `https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-arm64.tar.gz`.
- Версия закреплена `scripts/build/runtime-lock.json`; SHA-256 архива `436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26` совпал с `deploy/sing-box-1.14.4-linux-arm64.sha256`.
- Linux ARM64 ELF SHA-256: `d953af885f11d6b547c21a3c0ffe70796963afc802fab959d548311002b4908a`; тот же хеш был получен после переноса на роутер.
- ELF: AArch64, динамический интерпретатор `/lib/ld-linux-aarch64.so.1`, зависимости `libdl.so.2`, `libpthread.so.0`, `libc.so.6`. Роутер не имеет штатного `/lib/ld-linux-aarch64.so.1`; уже существующий `/opt/lib/ld-linux-aarch64.so.1` указывает на `ld-2.27.so`, а библиотеки доступны в `/opt/lib`.
- Вызов `/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib --list ./sing-box` разрешил все три библиотеки. ELF не изменялся; ссылки, библиотеки и пути роутера не менялись.
- Команда `.../ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box version` завершилась с кодом 0 и вывела `sing-box version 1.14.4`, `go1.26.10 linux/arm64`, `CGO: disabled`, revision `c005f35300ce76427dc285481ec5695f5b179cd2`.
- `.../ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box check -c ./singbox-loopback.json` завершилась с кодом 0.

## Loopback operation

JSON SHA-256: `31d4beee05f04278d43bfbb2e6f5d92b3b6852720ff39f223925a2a2795d1b61`. Вход слушал только `127.0.0.1:1080`; единственное прямое правило ограничено `127.0.0.1/32`, финальный outbound — `block`. Собственный статический тестовый HTTP-сервер слушал `127.0.0.1:18081` и отвечал фиксированным маркером. Клиент использовал SSH local forward и `curl --noproxy ''`, что исключило обход прокси для loopback.

Запрос завершился HTTP 200 и вернул `hestia-sing-box-loopback-ok`. Сохранённый журнал sing-box подтверждает входящее SOCKS-соединение с `127.0.0.1` к `127.0.0.1:18081` и outbound `direct` к тому же адресу в [sing-box.log](sing-box.log). Адрес интерфейса, шлюз и MAC из полного журнала в артефакт не включены.

Отдельная попытка проверить блокировку `127.0.0.2:18081` завершилась сбросом соединения до получения начального ответа SOCKS5 (`curl` сообщил код 97). Она выполнялась после завершения ограниченного процесса; shell-обёртка также завершилась ошибкой при присваивании специальной read-only переменной zsh `status`. Поэтому эта попытка не подтверждает блокировку и считается неинформативной. Повторять проверку другого адреса в рамках этого прогона не стали. Вывод про `block` основан на проверенной конфигурации, а не на отрицательной сетевой пробе. Тест производительности, VPN peer и TUN не выполнялись.

## Маршрутизация и очистка

Хеши IPv4/IPv6 маршрутов и правил совпали до и после; значения сохранены в [route-rule-hashes.json](route-rule-hashes.json). Сырые записи не сохранялись. Запущенный через loader процесс sing-box и тестовый HTTP helper завершились по 60-секундному shell watchdog; после завершения каталог `/opt/tmp/hestia-singbox-loopback.20261106-2045` удалён. При финальной проверке PID 23422 и 23421 уже завершились, других процессов sing-box/helper в списке не было. Временный SSH port forward закрыт.

При первой попытке передачи современный SCP согласовал SFTP, которого нет в Entware (`/opt/libexec/sftp-server` отсутствует). Передача повторена протоколом `scp -O`, после чего удалённый SHA-256 проверен. Событие не повлияло на состояние роутера.

## Локальная проверка помощника

`loopback-http.go` отформатирован `gofmt`, собран как Linux ARM64 с Go `1.27.3`, `CGO_ENABLED=0`, `GOTOOLCHAIN=local`, `GOPROXY=off`, `-trimpath -buildvcs=false`; ELF определён статическим ARM64. Повторная сборка из финального пути теми же флагами воспроизвела SHA-256 `59ed5854886f0d15722c5322f65ce1c5a27151a7f36657b41358fa34fb1f163f`. Команда сборки:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOPROXY=off \
  go build -trimpath -buildvcs=false -o /tmp/hestia-keenetic-loopback-http-final \
  experiments/keenetic-capabilities/prototype/singbox/loopback-http.go
```

`gofmt -d`, `go vet` и JSON policy assertions завершились без ошибок. Полная копия проверок и наблюдаемого `version`-вывода находится в [runtime-checks.txt](runtime-checks.txt). Независимая проверка сохранённых материалов и сборки helper находится в [validation.txt](validation.txt).
