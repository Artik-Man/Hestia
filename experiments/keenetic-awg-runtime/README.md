# Совместимость awg-tools с Keenetic Giga KN-1012

## Вопрос и статус

Можно ли запустить pinned `awg-tools` на KN-1012 через имеющийся Entware loader или подготовить совместимый static ARM64 вариант? Ограниченная проверка завершена 6 ноября 2026 года.

Результат разделяется по способу поставки. Динамический Linux ARM64 `awg` из комплекта Hestia не запускается через Entware loader: устройство использует glibc 2.27, а бинарник требует `GLIBC_2.33` и `GLIBC_2.34`. Статическая сборка из закреплённого официального исходника успешно вывела версию и справку на самом устройстве. Это подтверждает совместимость только интерфейса командной строки в этих двух read-only режимах. Поддержка AWG daemon, UAPI, TUN и VPN не проверялась.

## Среда и артефакты

KN-1012 сообщил read-only preflight: hostname `Keenetic-G-8919`, Linux kernel `4.9-ndm-5`, `aarch64`. На устройстве обнаружен `/opt/lib/ld-linux-aarch64.so.1 -> ld-2.27.so` и `/opt/lib/libc.so.6 -> libc-2.27.so`.

Исходник: официальный `amnezia-vpn/amneziawg-tools` tag `v3.1.20260812`, commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`. Динамический бинарник из Hestia `20261106-170213-66bb2faafc3c` имеет SHA-256 `7b5d8177fba2ebe1454390c069f7385401f95449c6f680e03090d368d7f16a56`, ELF interpreter `/lib/ld-linux-aarch64.so.1`, dependency `libc.so.6`.

На устройстве в приватном `/opt/tmp` проверены два артефакта: динамический pinned binary и static ELF, собранный из того же pinned source Zig 0.17.1 для `aarch64-linux-musl`. Хеши, происхождение Zig, команды, выводы, коды завершения и очистка находятся в [свидетельствах](evidence/). Статический бинарник доступен вне Git в `dist/keenetic-awg-runtime/` для локального воспроизведения.

Официальный upstream release публикует Ubuntu 22.04 и Alpine 3.19 assets; workflow собирает их нативно на `ubuntu-latest` без ARM64 cross target. Готового официального ARM64/static артефакта в этом релизе не обнаружено. Проверенный static вариант является нашей временной сборкой из upstream, не официально опубликованным бинарником. [Release](https://github.com/amnezia-vpn/amneziawg-tools/releases/tag/v3.1.20260812), [workflow](https://github.com/amnezia-vpn/amneziawg-tools/blob/master/.github/workflows/linux-build.yml), [сборка прототипа](prototype/README.md).

## Ожидаемый результат

Для динамического binary ожидался успешный запуск через `/opt/lib/ld-linux-aarch64.so.1 --library-path /opt/lib`; если несовместимость libc останется — сборка pinned upstream source в static ARM64 и запуск только `--version`/`--help`. Любая команда VPN, чтение конфигурации/ключей, создание интерфейсов или изменение маршрутов исключены.

## Фактический результат

Первый запуск dynamic binary напрямую ранее завершался кодом 127: shell не находил interpreter `/lib/ld-linux-aarch64.so.1`. Существующий Entware loader найден. Повторный запуск через него, после подтверждения host/device SHA, дошёл до библиотек Entware, но завершился кодом 1 с ошибками недостающих symbol versions `GLIBC_2.33` и `GLIBC_2.34`. `--help` также не смог начаться.

Static ARM64 build использовал upstream commit выше и Zig 0.17.1; ELF file inspection сообщил `statically linked`. После сверки переданного SHA с host binary прямой запуск на KN-1012 завершился успешно: `--version` code 0, `amneziawg-tools v3.1.20260812`; `--help` code 0, справка выведена. Каждый из моих remote temp каталогов удалён. [Динамический запуск](evidence/loader-run.txt), [static build](evidence/static-build.txt), [static запуск и cleanup](evidence/static-router-run.txt). Независимый тестировщик сверил текстовые протоколы, хеши, commit и локальный ELF; проверка на устройстве не повторялась. [Заключение независимой проверки](evidence/validation.txt).

## Воспроизведение

См. [инструкцию сборки](prototype/README.md). Передавать static binary нужно с проверкой SHA-256 на хосте и устройстве в новом каталоге `/opt/tmp`. Ограничиться `--version` и `--help`; очищать только свой временный каталог. Воспроизводимый протокол конкретного запуска содержится в [evidence](evidence/static-router-run.txt).

## Границы вывода

Подтверждено: конкретная статическая сборка `awg-tools v3.1.20260812` начинает выполнение на KN-1012 и завершает только безопасные `--version` и `--help`. Не подтверждены: корректная работа всех команд, AmneziaWG userspace daemon, kernel UAPI, наличие совместимого AWG kernel module, TUN, handshakes, передача пакетов, firewall/policy routing, DNS, fail-closed, производительность, запуск службы или восстановление после отказа. Прямой запуск бинарника, его version/help, сам по себе не является доказательством поддержки VPN.
