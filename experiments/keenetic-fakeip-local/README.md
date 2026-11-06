# Локальное соответствие sing-box FakeIP на Keenetic KN-1012

6 ноября 2026 года на Keenetic Giga KN-1012 проверено, что sing-box 1.14.4 возвращает синтетический FakeIP для собственного имени `.test`, восстанавливает имя при TCP- и UDP-запросах SOCKS5 к числовому адресу и подключается к локальным маркерам. Отдельно подтверждено сохранение соответствия FakeIP в приватном cache-файле через штатный перезапуск sing-box. Тестовый клиент, DNS-ответчик и обе цели работали только на loopback самого устройства.

## Вопрос и критерии

Опыт проверял, может ли клиент один раз получить синтетический IPv4 FakeIP и передать этот числовой адрес sing-box через SOCKS5, после чего sing-box восстановит домен и направит запрос к собственному loopback-маркеру.

Критерии:

1. Для `service.fakeip-local.test` sing-box выдаёт адрес из выделенного синтетического диапазона `198.18.0.0/24`.
2. SOCKS5 TCP CONNECT и UDP ASSOCIATE к числовому FakeIP на порты маркеров возвращают точные ожидаемые строки.
3. Журнал sing-box показывает восстановленное имя домена и выбор разрешённого outbound; собственный DNS-ответчик возвращает для этого имени `127.0.0.1`.
4. Маршруты и правила IPv4/IPv6 не меняются, а после работы не остаются процессы, слушатели или временные каталоги пробы.
5. В отдельном ограниченном прогоне `store_fakeip` сохраняет это же соответствие при перезапуске sing-box. Клиент повторно не отправляет DNS-запрос, но TCP и UDP запросы к сохранённому FakeIP снова получают маркеры.

## Среда и проверенная схема

- Физическое устройство: Keenetic Giga KN-1012, ARM64, KeeneticOS с Linux `4.9-ndm-5`.
- Runtime: официальный sing-box 1.14.4, версия и SHA-256 совпали с закреплённым проектом артефактом: `d953af885f11d6b547c21a3c0ffe70796963afc802fab959d548311002b4908a`. Запуск — через уже установленный `/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib`; файлы загрузчика, библиотеки и пакеты не менялись.
- Архив и источник бинарника описаны в [предыдущей проверке runtime](../keenetic-capabilities/evidence/singbox-loopback-20261106/run-manifest.md); перед обоими успешными прогонами удалённые SHA-256 sing-box, helper и конфигурации совпали с локальными.
- Официальная схема 1.14.4 подтверждена по [Fake IP DNS server](https://sing-box.sagernet.org/configuration/dns/server/fakeip/) и по [исходнику fakeip.Store тега v1.14.4](https://raw.githubusercontent.com/SagerNet/sing-box/v1.14.4/dns/transport/fakeip/store.go). Тегged исходник показывает: store использует cache-file storage при `StoreFakeIP`, восстанавливает metadata при совпадении диапазонов и возвращает ранее сохранённый адрес по домену. Конфигурация использует актуальный `dns.servers[].type = "fakeip"`, а не удалённый legacy `dns.fakeip`. Опция `experimental.cache_file.store_fakeip` описана в [документации cache file](https://sing-box.sagernet.org/configuration/experimental/cache-file/) и прошла проверку именно бинарником 1.14.4 на устройстве.
- Синтетический DNS-ответчик принимал только точное имя `service.fakeip-local.test.` и A-запрос, отвечая `127.0.0.1` с TTL 30 секунд. DNS FakeIP-ответ на запрос клиента имел TTL 600.
- Loopback порты: SOCKS `127.0.0.1:19350`, DNS ingress `127.0.0.1:19351`, синтетический резолвер `127.0.0.1:19352`, TCP-маркер `127.0.0.1:19353`, UDP-маркер `127.0.0.1:19354`. Все порты 19350–19359 проверялись перед запуском.
- Конфигурация направляла только `.test` домен на outbound `loopback-only`; окончательное действие маршрута было `block`. DNS upstream был задан числовым loopback-адресом. Диапазон `198.18.0.0/24` применялся только как логический FakeIP и не добавлялся в таблицу маршрутизации, не назначался интерфейсу и не использовался для обходного dial.

## Комплект

- [Go helper](prototype/fakeip-harness.go) поднимает только собственные loopback DNS/TCP/UDP endpoint и выполняет ограниченные DNS/SOCKS пробы. Все его функции документированы.
- [Основная конфигурация](prototype/singbox-fakeip.json) предназначена для базовой проверки отображения и TCP/UDP потоков без cache-file.
- [Конфигурация cache-file](prototype/singbox-fakeip-cache.json) включает только приватный `experimental.cache_file.store_fakeip` с отдельным `cache_id`.
- Снимки исходника и конфигураций, литеральные команды, UTC, SHA-256 и сырые журналы сохранены в `evidence/attempt-basic-1/` и `evidence/attempt-persistence-1/`. Бинарный cache-файл не копировался в репозиторий; записаны его SHA-256 и размер.

## Фактические результаты

| Проверка | Результат |
|---|---|
| Схема основного файла на sing-box 1.14.4 | `check` exit 0; config SHA `0a91e3a31bea297945bf4915534a205da4db6bc8aa0707256397042713a6bb09` |
| DNS клиента | `service.fakeip-local.test.` → `198.18.0.2`; helper сохранил единственную клиентскую DNS-выдачу в `fakeip.txt` |
| SOCKS TCP | Запрос к числовому `198.18.0.2:19353` вернул `HSTIA-FAKEIP-TCP-19353` |
| SOCKS UDP | UDP ASSOCIATE к числовому `198.18.0.2:19354` вернул `HSTIA-FAKEIP-UDP-19354` |
| Восстановление домена | Журнал содержит `found fakeip domain: service.fakeip-local.test`, выбор `.test` правила `loopback-only` и `outbound connection to service.fakeip-local.test:<port>` |
| Фактическое назначение | Synthetic resolver вернул `127.0.0.1`; собственные TCP и UDP endpoint зафиксировали по одному маркеру на каждый базовый поток |
| Cache-file после рестарта | При `store_fakeip: true` первое и второе клиентские подключения использовали `198.18.0.2`; второй helper режим пишет `reuses_saved_fakeip=198.18.0.2 without DNS lookup` |
| Проверка после restart | Второй процесс sing-box снова записал `found fakeip domain: service.fakeip-local.test`; TCP и UDP маркеры получены повторно без клиентского DNS запроса |
| Cache file | Размер 32,768 байт; SHA-256 перед restart `a3b23c4a3ce6a92038bc4236416f673fa01a82a2fecdd47409f907d6b4745962`, после второго штатного завершения `8555029d8fe4c41d3dda94f1e0517ec2ea1068322a0a4a662efae1cb8c87a10c` |
| IPv4/IPv6 routes и rules | Все 4 SHA-256 до и после совпали в обоих успешных запусках; сырые таблицы не сохранялись |
| Очистка | Оба sing-box процесса штатно завершились с `wait` exit 0; helper завершён точным PID; проверены отсутствие PID, удаление обоих каталогов и свободные порты 19350–19354 |

Основные свидетельства: [transcript базового запуска](evidence/attempt-basic-1/device-transcript.txt), [сырые логи базового запуска](evidence/attempt-basic-1/remote-output/), [проверка и очистка базового запуска](evidence/attempt-basic-1/post-run-verification.txt); [transcript cache/restart](evidence/attempt-persistence-1/device-transcript.txt), [сырые логи обеих сторон restart](evidence/attempt-persistence-1/remote-output/), [cache metadata и финальные hashes](evidence/attempt-persistence-1/post-run-verification.txt), [финальная очистка](evidence/final-cleanup.txt).

Во время работы строгий синтетический DNS helper также отклонил посторонние query type, которые sing-box отправлял помимо A. Это отражено в raw log. Все необходимые A-запросы для двух маркерных потоков успешно обработаны; тестовый DNS listener не обращался к внешним резолверам.

## Неудачные попытки и коррекции

- Первый вариант конфига завершил `sing-box check` с `default server cannot be fakeip`. В новой DNS-схеме default server был установлен в `synthetic-real-dns`, а правило `.test` оставлено направленным на FakeIP. Неудачная проверка сохранена в `evidence/attempt-20261106T1905Z/validation.txt`.
- Один запуск не дошёл до sing-box: readiness grep ожидал строку с начала, но Go logger добавлял timestamp. Исправленный runner проверяет фактическую подстроку и использует новый каталог; журнал неуспешного запуска и PIDs находятся в `evidence/attempt-live-1/`.
- Следующая проверка прошла схему, но при запуске sing-box сообщил `detour to an empty direct outbound makes no sense`. Удалено только поле DNS `detour`; upstream уже задан числовым `127.0.0.1`. Ошибка и SHA cache-файла startup-попытки находятся в `evidence/attempt-live-2/`; случайно выведенные байты cache удалены из репозитория и сохранены только в локальном `/private/tmp` с записанными SHA и размером.
- Перед cache-прогоном попытка `cp` из уже удалённого временного каталога завершилась до переноса данных. Runtime и helper затем были повторно загружены прямо из проверенных локальных входов; итоговые удалённые хеши совпали. Это событие не повлияло на базовый или cache результат.

## Проверки кода и воспроизведение

Для Go helper выполнены `gofmt -d`, `go vet` и статическая Linux/ARM64 сборка. Все завершились с кодом 0. Итоговый helper SHA-256 — `634c232d6bf231c17655e4015be8c333375806b385d5e1a6b7462e92762f2c78`; [команды и результаты](evidence/local-gofmt.txt), [vet](evidence/local-go-vet.txt), [сборка](evidence/local-build.txt). Shell runner-ы проверены `sh -n`; ShellCheck 0.11.0 завершился с кодом 0. `shfmt 3.11.0 -d -i 4 -ci` показал только split двух последовательностей `printf; cat`; исходные файлы runner-ов сохранены без изменения, поскольку это исполнявшиеся источники конкретных попыток. Диагностика shfmt и ShellCheck сохранена в `evidence/shell-shfmt-diff.txt` и `evidence/shell-shellcheck.txt`. Координатор выполнил общие `make fmt` и `make check`: обе команды прошли. Эти проверки не заменяют аппаратные прогоны, описанные выше.

Чтобы повторить базовый прогон, сначала проверьте host key `ED25519 SHA256:u5mFSUOHtvmfjURyMmAe8N2BVONvSiTAoV7OLn2Czoo`, наличие установленного loader и свободные порты. Затем создайте новый каталог `/opt/tmp` с правами 0700, перенесите закреплённый runtime, собранный helper и `prototype/singbox-fakeip.json`, сверяйте удалённые SHA, запускайте `sing-box check`, после чего исполняйте сохранённую последовательность из [runner базового опыта](evidence/attempt-basic-1/device-run.sh). Для persistence используйте `prototype/singbox-fakeip-cache.json` и [runner restart опыта](evidence/attempt-persistence-1/device-run.sh). Каждый повтор должен использовать новый каталог и те же границы loopback; не переносите FakeIP в маршруты, интерфейсы или внешние назначения.

Независимая сверка исходников, свидетельств и очистки: [validation.txt](evidence/validation.txt).

## Границы вывода

Подтверждён механизм sing-box 1.14.4 FakeIP на одном физическом KN-1012 с зафиксированным диапазоном и одним synthetic `.test` именем. Успешное сохранение кэшированного соответствия показано на одном чистом restart процесса с тем же конфигом и cache-id.

Не проверялись клиентский трафик с отдельного LAN устройства, system DNS, DNS interception на порту 53, DHCP, клиентский tun/TProxy, маршруты/политики Hestia, DNS TTL обновления, смена реального IP, истечение или reuse адресов после TTL, несколько доменов/групп, cache corruption, внезапное обесточивание и восстановление после изменения конфигурации/range. Это не доказывает полную сохранность всех параметров DNS или пригодность persistence как production кэша Hestia.
