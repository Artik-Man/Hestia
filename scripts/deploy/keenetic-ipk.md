# Ручная поставка экспериментального IPK на Keenetic

Эта процедура описывает ручное обновление Entware-пакета Hestia на KN-1012. Keenetic-поставка остаётся экспериментальной: `scripts/deploy/run.py --type keenetic` намеренно завершает работу до подключения, а IPK не выполняет транзакционный откат при ошибке `postinst`. Перед любым подключением к физическому роутеру требуется отдельное поручение владельца и согласованное окно обслуживания.

## Сборка и выбор артефакта

Собирайте IPK поддерживаемым сценарием из корня репозитория. Подробности о закреплённых runtime-входах и проверке манифеста приведены в [инструкции сборки](../build/readme.md).

```sh
make build
```

Выберите `.ipk` именно из каталога `keenetic-arm64-experimental` одного завершённого запуска сборки. Повторно проверьте манифест всего каталога, затем не пересобирайте пакет между сверкой хеша и доставкой:

```sh
python3 -c 'import sys; from pathlib import Path; sys.path.insert(0, "scripts/shared"); from common import verify_bundle; print(verify_bundle(Path("/absolute/path/to/keenetic-arm64-experimental"))["version"])'
```

Запишите версию из имени пакета и локальную контрольную сумму:

```sh
IPK=/absolute/path/to/hestia_<version>_aarch64-3.10.ipk
shasum -a 256 "$IPK"
```

## Управляющий доступ и передача пакета

SSH используется только для запуска удалённых команд. Передача бинарников и IPK выполняется через уже запущенный HTTP-сервер `hestia-cli` на доверенном LAN-адресе. Не используйте SCP/SFTP и не передавайте содержимое файлов через stdin SSH. При первой установке `hestia-cli` сервер должен быть заранее установлен и настроен вне SSH-передачи; он не может загрузить сам себя.

Используйте только настроенный SSH alias `keenetic-hestia` из приватного файла `private/keenetic/ssh/config`. Конфигурация закрепляет host key; не отключайте проверку ключа и не подключайтесь по непроверенному адресу/ключу. Не копируйте содержимое приватной конфигурации, закрытые ключи, RCI token или значения секретов в документацию, отчёты, команды либо журналы.

```sh
SSH_CONFIG=private/keenetic/ssh/config
ssh -F "$SSH_CONFIG" keenetic-hestia 'id -u; /opt/bin/opkg print-architecture'
```

Проверьте, что `hestia-cli` отвечает на LAN URL, локальный token-файл доступен и закрыт от остальных пользователей. Сервер принимает пакеты в `/opt/var/lib/hestia-cli/inbox`; размер одного файла ограничен 128 MiB. HTTP доступ разрешён только из доверенной LAN, сервер должен оставаться привязан к LAN-адресу.

```sh
HESTIA_CLI_URL=http://192.168.1.1:8081
HESTIA_CLI_TOKEN_FILE=private/hestia-cli.token
REMOTE_INBOX=/opt/var/lib/hestia-cli/inbox
IPK_NAME=$(basename "$IPK")
LOCAL_SHA=$(shasum -a 256 "$IPK" | awk '{print $1}')
test -r "$HESTIA_CLI_TOKEN_FILE"
curl --disable --fail-with-body --connect-timeout 5 --max-time 600 \
  --config - --upload-file "$IPK" \
  "$HESTIA_CLI_URL/v1/files/upload/$IPK_NAME" <<EOF
header = "Authorization: Bearer $(cat "$HESTIA_CLI_TOKEN_FILE")"
EOF
REMOTE_SHA=$(ssh -F "$SSH_CONFIG" keenetic-hestia \
  "sha256sum '$REMOTE_INBOX/$IPK_NAME' | cut -d ' ' -f 1")
test "$LOCAL_SHA" = "$REMOTE_SHA" || { printf '%s\n' 'IPK hash mismatch'; exit 1; }
```

Если hash не совпал, не запускайте `opkg`; удалённую копию можно удалить отдельной SSH-командой после проверки точного пути.

## Preflight и резервная копия

До обновления подтвердите, что это KN-1012 с ожидаемой прошивкой и архитектурой Entware, `/opt` имеет достаточно свободного места, root-only RCI token подготовлен отдельно, а текущий Hestia supervisor готов. Lifecycle hook пакета также выполняет аппаратный preflight, но он не заменяет сохранение состояния до запуска `opkg`.

Зафиксируйте до установки:

- `opkg status hestia` и текущую версию;
- вывод `/opt/bin/hestia -service-supervisor-ready` и наличие `/opt/var/run/hestia/supervisor.ready`;
- SHA-256 default IPv4 route snapshot, полученный из `ip -4 route show default | sha256sum`;
- SHA-256 default IPv6 route snapshot, если IPv6 default route используется;
- SHA-256 нового IPK и предыдущего исправного rollback IPK.

Сохраните конфигурацию и статус пакетов в закрытый каталог. На BusyBox роутера `tar` не умеет создавать архив, поэтому копируйте каталог через `cp -R`; не меняйте права копии на более открытые. В `/opt/etc/hestia` могут находиться token и другие секреты.

```sh
BACKUP=/opt/tmp/hestia-deploy-<run-id>
ssh -F "$SSH_CONFIG" keenetic-hestia "umask 077; mkdir -m 700 '$BACKUP'; cp -R /opt/etc/hestia '$BACKUP/etc-hestia'; cp /opt/lib/opkg/status '$BACKUP/opkg-status'; chmod -R go-rwx '$BACKUP'; ls -ld '$BACKUP' '$BACKUP/etc-hestia'"
```

Убедитесь, что каталог резервной копии принадлежит root и доступен только root. Передайте предыдущий известный исправный IPK через тот же HTTP upload endpoint, затем сохраните его в backup-каталог удалённой командой и сверьте SHA-256 с локальным доверенным экземпляром:

```sh
PREVIOUS_IPK=/absolute/path/to/hestia_<previous-version>_aarch64-3.10.ipk
PREVIOUS_NAME=$(basename "$PREVIOUS_IPK")
PREVIOUS_SHA=$(shasum -a 256 "$PREVIOUS_IPK" | awk '{print $1}')
curl --disable --fail-with-body --connect-timeout 5 --max-time 600 \
  --config - --upload-file "$PREVIOUS_IPK" \
  "$HESTIA_CLI_URL/v1/files/upload/$PREVIOUS_NAME" <<EOF
header = "Authorization: Bearer $(cat "$HESTIA_CLI_TOKEN_FILE")"
EOF
REMOTE_PREVIOUS_SHA=$(ssh -F "$SSH_CONFIG" keenetic-hestia \
  "umask 077; cp '$REMOTE_INBOX/$PREVIOUS_NAME' '$BACKUP/$PREVIOUS_NAME'; chmod 0600 '$BACKUP/$PREVIOUS_NAME'; sha256sum '$BACKUP/$PREVIOUS_NAME' | cut -d ' ' -f 1")
test "$REMOTE_PREVIOUS_SHA" = "$PREVIOUS_SHA" || { printf '%s\n' 'Rollback IPK hash mismatch'; exit 1; }
```

Сравните удалённый хеш с `PREVIOUS_SHA`. Не удаляйте backup и rollback IPK до успешного post-install smoke.

## Установка и post-install smoke

Только после preflight, совпадения хешей и проверки резервной копии выполните установку от root. `configure-package` ждёт readiness не дольше 47 минут, чтобы не прервать supervisor раньше его предельного boot recovery:

```sh
ssh -F "$SSH_CONFIG" keenetic-hestia \
  "/opt/bin/opkg install '$REMOTE_INBOX/$IPK_NAME'"
```

Успешное завершение требует одновременно:

1. `opkg status hestia` показывает ожидаемую `Version`, `Architecture: aarch64-3.10` и `Status: install user installed`.
2. `/opt/bin/hestia -service-supervisor-ready` завершается с кодом 0, readiness marker существует и не является ссылкой; package-maintenance marker отсутствует.
3. Профиль и конфигурация controller проходят предусмотренные пакетные проверки; панель на loopback и LAN API отвечают ожидаемыми статусами. Для операций только чтения можно проверить `/`, `/api/groups-and-rules` и `/api/physical-connections` с разрешённого LAN-клиента.
4. Default IPv4 и используемый IPv6 route hashes совпадают с исходными снимками.
5. В журнале supervisor нет ошибки запуска, а каталог конфигурации и секреты сохранили root-only права.

Записывайте версию, локальный и удалённый хеш IPK, opkg status, readiness, HTTP-коды и route hashes в evidence. Не сохраняйте RCI token, закрытые ключи или содержимое профиля с секретами. Описание проверенных возможностей и текущих ограничений находится в [отчёте IPK](../../experiments/keenetic-ipk-packaging/README.md).

## Отказ и восстановление

Если `opkg install` или `postinst` завершается ошибкой, считайте пакетное состояние частичным: `opkg` может оставить `Status: install user unpacked`, старые процессы уже могут быть остановлены, а `.opkg` sidecars — созданными. Автоматического транзакционного rollback нет. Не повторяйте `opkg install` вслепую и не удаляйте sidecars или package-maintenance marker до выяснения причины.

Сначала сохраните код/текст ошибки, `opkg status hestia`, безопасный tail supervisor log, readiness, наличие процессов и route hashes. Не включайте в отчет секреты и полный профиль. Если ошибка говорит о невалидном managed profile, отдельно проверьте профиль и его ссылки. `opkg configure hestia` допустим только после установления transient readiness-причины и подтверждения валидности профиля; он не исправляет профиль, который не проходит проверку.

Когда откат выбран как восстановление, сначала убедитесь, что profile validator проходит на текущей конфигурации, и проверьте условия lifecycle hook. Используйте сохранённый предыдущий IPK и резервную копию конфигурации, сверив их хеши и права. Команда ручного понижения версии:

```sh
ssh -F "$SSH_CONFIG" keenetic-hestia \
  "/opt/bin/opkg install --force-downgrade --force-reinstall '$BACKUP/$PREVIOUS_NAME'"
```

После команды повторите весь post-install smoke и сравните route hashes. Если пакет не поднимается или причина не установлена, остановитесь и передайте диагностические сведения владельцу; не удаляйте рабочие данные роутера ради очистки статуса `opkg`. Фактический неуспешный прогон 9 ноября 2026 года описан отдельно в [отчёте опыта](../../experiments/keenetic-ipk-packaging/README.md#неудачное-обновление-keenetic-9-ноября-2026-года).

`prerm` намеренно отказывается удалять принадлежащий Hestia OpkgTun0, если полный read-only RCI snapshot показывает, что хотя бы одна Keenetic policy разрешает этот интерфейс. В такой ситуации не отключайте policy и не обходите lifecycle guard без отдельного решения владельца: удаление интерфейса изменяет сетевое поведение. Установка сохранённой версии поверх unpacked состояния также может не восстановить сервис, если `postinst` продолжает отклонять managed profile. При профиле, который не проходит валидатор, не повторяйте `opkg configure` и остановитесь после сбора безопасной диагностики.
