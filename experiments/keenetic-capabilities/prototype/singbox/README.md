# Совместимый sing-box: loopback-прототип

Этот комплект проверяет конкретный официальный ARM64 бинарник sing-box 1.14.4 на Keenetic KN-1012, используя уже имеющийся Entware glibc loader. Он запускает только временный SOCKS listener на `127.0.0.1` и собственный HTTP endpoint на `127.0.0.1`; другие адреса конфигурация направляет в block outbound. Прототип не меняет ELF, файлы loader, пакеты, службы, маршруты, правила или firewall.

## Входы и локальная проверка

Официальный архив: `https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-arm64.tar.gz`. Его SHA-256 закреплён в `scripts/build/runtime-lock.json` и `deploy/sing-box-1.14.4-linux-arm64.sha256`:

```sh
curl -fL --proto '=https' --proto-redir '=https' \
  -o /tmp/sing-box-1.14.4-linux-arm64.tar.gz \
  https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-arm64.tar.gz
printf '%s  %s\n' \
  436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26 \
  /tmp/sing-box-1.14.4-linux-arm64.tar.gz | shasum -a 256 -c -
mkdir -p /tmp/sing-box-1.14.4-linux-arm64
tar -xzf /tmp/sing-box-1.14.4-linux-arm64.tar.gz \
  -C /tmp/sing-box-1.14.4-linux-arm64 \
  --strip-components=1 \
  sing-box-1.14.4-linux-arm64/sing-box
shasum -a 256 /tmp/sing-box-1.14.4-linux-arm64/sing-box
```

Ожидаемый хеш исполняемого ELF: `d953af885f11d6b547c21a3c0ffe70796963afc802fab959d548311002b4908a`. Помощник, который отдаёт фиксированный маркер только по loopback, соберите из этого каталога проекта:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOPROXY=off \
  go build -trimpath -buildvcs=false \
  -o /tmp/hestia-keenetic-loopback-http \
  experiments/keenetic-capabilities/prototype/singbox/loopback-http.go
```

Ожидаемый SHA-256 helper: `59ed5854886f0d15722c5322f65ce1c5a27151a7f36657b41358fa34fb1f163f`. Перед исполнением сверяйте локальные входы; не используйте скачанный артефакт до успешной проверки суммы.

## Перенос и проверка runtime

Укажите SSH-идентичность с тем же проверенным host key, который используется для KN-1012. В этом прогоне использовались `StrictHostKeyChecking=yes`, пользователь root и порт 222. Временный каталог создавайте с правами 0700 и только если его ещё нет. Ниже показан каталог фактического прогона; при повторе выберите новый уникальный путь:

```sh
ssh -p 222 -i "$HOME/.ssh/hestia_keenetic" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  root@192.168.1.1 \
  'umask 077; mkdir /opt/tmp/hestia-singbox-loopback.20261106-2045 && chmod 700 /opt/tmp/hestia-singbox-loopback.20261106-2045'
scp -O -p -P 222 -i "$HOME/.ssh/hestia_keenetic" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  /tmp/sing-box-1.14.4-linux-arm64/sing-box \
  /tmp/hestia-keenetic-loopback-http \
  experiments/keenetic-capabilities/prototype/singbox/singbox-loopback.json \
  root@192.168.1.1:/opt/tmp/hestia-singbox-loopback.20261106-2045/
```

`scp -O` нужен только если на целевой Entware нет `sftp-server`. Он сохраняет обязательную проверку host key. Убедитесь, что SHA-256 на роутере совпадают с локальными; затем проверьте список зависимостей и две безопасные команды:

```sh
ssh -p 222 -i "$HOME/.ssh/hestia_keenetic" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  root@192.168.1.1 '
    cd /opt/tmp/hestia-singbox-loopback.20261106-2045
    /opt/bin/sha256sum sing-box hestia-keenetic-loopback-http singbox-loopback.json
    /opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib --list ./sing-box
    /opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box version
    /opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib ./sing-box check -c ./singbox-loopback.json
  '
```

Не меняйте бинарник и не создавайте путь `/lib/ld-linux-aarch64.so.1`. Если текущий Entware loader не разрешает все зависимости или команда версии/check не проходит, остановите опыт.

## Ограниченный запуск и запрос

Перед запуском запишите только SHA-256 следующих команд, не сохраняя сырые сетевые записи:

```sh
ip -4 route show table all | sha256sum
ip -4 rule show | sha256sum
ip -6 route show table all | sha256sum
ip -6 rule show | sha256sum
```

Запустите процессы в одной SSH-команде с точными PID, `EXIT` cleanup и внутренним 60-секундным watchdog. Сервер сам также ограничивает жизнь 70 секундами:

```sh
ssh -p 222 -i "$HOME/.ssh/hestia_keenetic" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  root@192.168.1.1 '
    set -eu
    D=/opt/tmp/hestia-singbox-loopback.20261106-2045
    cd "$D"
    ./hestia-keenetic-loopback-http --duration=70s >http.log 2>&1 &
    HTTP_PID=$!
    /opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib \
      ./sing-box run -c ./singbox-loopback.json >sing-box.log 2>&1 &
    BOX_PID=$!
    trap '\''kill -TERM "$BOX_PID" "$HTTP_PID" 2>/dev/null || true; wait "$BOX_PID" 2>/dev/null || true; wait "$HTTP_PID" 2>/dev/null || true'\'' EXIT
    trap '\''exit 129'\'' HUP
    trap '\''exit 130'\'' INT
    trap '\''exit 143'\'' TERM
    sleep 60
  '
```

Пока эта SSH-команда активна, откройте вторую проверенную SSH-сессию с локальным перенаправлением `-N -L 127.0.0.1:11082:127.0.0.1:1080`. Затем отправьте только приведённый ниже положительный loopback-запрос. Пустое значение `--noproxy` предотвращает обход прокси из-за настройки `NO_PROXY` рабочей станции:

```sh
curl --noproxy '' --fail --silent --show-error --verbose --max-time 8 \
  --socks5-hostname 127.0.0.1:11082 http://127.0.0.1:18081/
```

Expected body: `hestia-sing-box-loopback-ok`. The SOCKS client uses a numeric loopback destination. Do not send traffic to non-loopback addresses. After the watchdog or exact-PID cleanup finishes, compare the four route/rule hashes and remove only the experiment's own temporary directory:

```sh
ssh -p 222 -i "$HOME/.ssh/hestia_keenetic" \
  -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
  root@192.168.1.1 \
  'rm -rf -- /opt/tmp/hestia-singbox-loopback.20261106-2045 && test ! -e /opt/tmp/hestia-singbox-loopback.20261106-2045'
```

Не используйте `pkill` и не удаляйте неизвестные каталоги. Полный фактический протокол, хеши и границы вывода приведены в [отчёте Keenetic](../../README.md#совместимый-sing-box-loopback-прототип--6-ноября-2026-года).
