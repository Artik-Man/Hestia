# Локальный VLESS на KN-1012

6 ноября 2026 года на Keenetic Giga KN-1012 проверен локальный путь sing-box 1.14.4: SOCKS-клиент → VLESS-сервер на loopback → собственные TCP/UDP-ответчики на loopback. Валидный синтетический UUID прошёл обе пробы. Неверный UUID отклонён на TCP-пробе при живом сервере и доступном ответчике. Опыт не проверяет клиентский транзит, удалённый сервер или подключение через WAN.

## Вопрос и критерии

Проверить, что закреплённый sing-box поддерживает VLESS в роли локального клиента и сервера, передаёт уникальные TCP и UDP маркеры, а сервер отклоняет неверный UUID без доставки TCP-маркера. Прямые подключения к обоим ответчикам подтверждают их доступность. Счётчики, журнал `unknown UUID` и проверки PID отделяют отказ аутентификации от остановки процессов. Проба ограничена `127.0.0.1` и портами `19310–19319`; маршруты, правила, DNS, firewall и постоянная конфигурация не меняются.

## Среда и комплект

- Физический Keenetic Giga KN-1012, KeeneticOS 5.2 Beta 2, Linux `4.9-ndm-5`, `aarch64`.
- Официальный неизменённый sing-box 1.14.4; SHA-256 ELF `d953af885f11d6b547c21a3c0ffe70796963afc802fab959d548311002b4908a`. Использован уже имеющийся `/opt/lib/ld-linux-aarch64.so.1` с `--library-path /opt/lib`; системные библиотеки и пакеты не менялись.
- `prototype/vless-server.json` слушает VLESS только на `127.0.0.1:19316` и принимает тестовый UUID `11111111-1111-4111-8111-111111111111`. Правильный UUID — `prototype/vless-local.json`; неверный UUID `22222222-2222-4222-8222-222222222222` — `prototype/vless-wrong-uuid.json`. Все значения синтетические.
- SOCKS слушатели: правильный UUID `127.0.0.1:19310`, неверный UUID `127.0.0.1:19311`. Ответчики: TCP `127.0.0.1:19312`, UDP `127.0.0.1:19313`.
- `prototype/vless-local-harness.go` собирался статически для Linux ARM64 Go `1.27.3` (`CGO_ENABLED=0`, `GOTOOLCHAIN=local`, `GOPROXY=off`). SHA-256 helper `01ac83304e486a1b8c4dfac9bb1d7d12d15ccd12b22899f085c50b1bf28dff12`.
- Локальные `gofmt -d`, `go vet` и ARM64 build прошли; результат: [local-checks.txt](evidence/local-checks.txt); версия toolchain зафиксирована в [local-toolchain.txt](evidence/local-toolchain.txt). Все три конфигурации отдельно прошли `sing-box check` на устройстве.

## Фактический результат

Критерии TCP/UDP и неверного UUID выполнены в одном ограниченном запуске. [Полный transcript попытки 08](evidence/attempt-08-run/transcript.txt) ссылается на отдельные сырые stdout/stderr, сохранённые автоматически. В журналах две startup-строки с топологией заменены явным маркером; правило редактирования применялось автоматическим `sed` из сохранённого скрипта [remote-run.sh](evidence/attempt-08-run/remote-run.sh). Остальные строки, включая таймстемпы и отказ UUID, сохранены.

| Проверка | Наблюдение |
|---|---|
| Прямой TCP-контроль | Получен `HESTIA-VLESS-TCP-19312`; счётчик стал 1 |
| Прямой UDP-контроль | Получен `HESTIA-VLESS-UDP-19313`; счётчик стал 1 |
| TCP через SOCKS → VLESS | Получен `HESTIA-VLESS-TCP-19312`; TCP-счётчик стал 2 |
| UDP через SOCKS → VLESS | Получен `HESTIA-VLESS-UDP-19313`; UDP-счётчик стал 2 |
| Неверный UUID, TCP | Сервер записал `unknown UUID: 22222222-2222-4222-8222-222222222222`; SOCKS-туннель не вернул маркер, TCP-счётчик остался `2 → 2` |
| Живые процессы | PID сервера и обоих клиентов проверены непосредственно до и после отрицательной пробы |
| Маршруты и правила | SHA-256 IPv4/IPv6 routes и rules совпали до и после |
| Очистка | Все четыре собственных PID завершены, порты `19310–19319` больше не слушались, временный каталог удалён и его отсутствие подтверждено |

Перенос выполнен отдельными файлами через `scp -O`; tar/zip архив не создавался. До запуска локальные и целевые SHA-256 sing-box, helper и конфигураций совпали. Host key проверялся `StrictHostKeyChecking=yes`; используемый ключ `192.168.1.1:222` имеет fingerprint `SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo`. Хеши артефактов и отдельные пробы сохранены в `evidence/attempt-03-manifest.txt`, `attempt-04-transfer.txt`, `attempt-05-target-hashes-checks.txt`, `attempt-07-check-individual.txt`, а очистка — в [attempt-09-device-cleanup.txt](evidence/attempt-09-device-cleanup.txt).

## Неудачные попытки

- [Попытка 01](evidence/attempt-01-preflight.txt) не установила SSH-соединение: локальная песочница вернула `Operation not permitted` до рукопожатия. Повторная read-only попытка с разрешённым сетевым доступом прошла; host key строго проверялся, занятых портов не было.
- [Попытка 05](evidence/attempt-05-target-hashes-checks.txt) вызвала неподдерживаемый флаг `sing-box --version`. Исполняемый файл остался неизменным, SHA-256 совпал. Команда исправлена на подкоманду `sing-box version`; конфигурации затем проверены независимо и завершились с кодом 0 ([попытка 07](evidence/attempt-07-check-individual.txt)).

Снимки исходника и конфигураций для upload и live run сохранены раздельно и неизменяемо вместе с manifest hashes в `evidence/attempt-03-source/` и `evidence/attempt-08-run/`. Повторный запуск не использует или не перезаписывает эти снимки.

## Воспроизведение и границы

Локальные проверки повторяются так:

```sh
gofmt -d experiments/keenetic-vless-local/prototype/vless-local-harness.go
GOTOOLCHAIN=local GOPROXY=off go vet ./experiments/keenetic-vless-local/prototype/vless-local-harness.go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOTOOLCHAIN=local GOPROXY=off \
  go build -trimpath -buildvcs=false -o /private/tmp/hestia-vless-local-harness \
  experiments/keenetic-vless-local/prototype/vless-local-harness.go
```

Для аппаратного повтора сохранён `evidence/attempt-08-run/remote-run.sh`; он выполнялся командой `ssh -p 222 -i ~/.ssh/hestia_keenetic -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes root@192.168.1.1 'sh -s' < evidence/attempt-08-run/remote-run.sh`. Скрипт предполагает уже проверенные файлы в своём private workdir и предназначен для повторного использования только после подготовки отдельного каталога, проверки host key, хешей и портов. Исходный рабочий каталог `/opt/tmp/hestia-vless-local.20261106-1905` удалён.

Отрицательная проба была только TCP: неверный UUID для UDP отдельно не проверялся. Успех подтверждает выбранную сборку sing-box и конфигурацию VLESS на одном KN-1012 при loopback-условиях. Он не подтверждает VPN до внешнего узла, поведение через WAN, транзит клиентских устройств, IPv6, производительность или устойчивость при обрывах сети.

## Независимая сверка

[Проверка свидетельств](evidence/validation.txt) воспроизвела SHA-256 helper из снимка исходника и подтвердила соответствие счётчиков, журнала UUID, состояний процессов и очистки заявленному результату. В манифесте самого прогона нет повторного хеширования ELF: идентичность исполняемых файлов опирается на предшествующую проверку целевых хешей и сохранение того же приватного каталога. Проверяющий к роутеру не обращался.
