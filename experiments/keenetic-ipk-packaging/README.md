# Локальная сборка IPK для Keenetic

## Исправление сохранения порядка групп на Keenetic — 12 ноября 2026 года

**Исправление блокировки ingress, 12 ноября 2026 года.** После обновления
встроенный журнал показывал, что правило `hestia-keenetic-ingress` всё ещё
указывает на `deny`, хотя в профиле безопасной целью служит группа «Остальной
мир». В `0.1.5` добавлено строгое восстановление этого конкретного расхождения;
повторное применение неизменённого порядка теперь может активировать только
починку маршрута, сохраняя настоящий no-op для остальных случаев. Установлен
IPK `0.1.5` (SHA-256
`873d60387e45e9eeca06da4d8e0e926490cb427b9773a9adf02e64fb518d568b`). Пакет,
supervisor и managed profile прошли проверки; точный текущий порядок отправлен
через API без изменения порядка групп. Установленный ingress route теперь
указывает на ID группы «Остальной мир». IPv4 default-route hash сохранился.

В журнале после исправления пока нет новых клиентских событий: OpkgTun0
отсутствует в политиках Keenetic, поэтому живой путь клиентского трафика через
Hestia не проверен. Исторические `deny` записи не являются результатом после
исправления. Подробности — в [протоколе](evidence/group-order-fix-20261112.txt).

**Вопрос и среда.** Исправляется ли 503 `PUT /api/group-order`, вызванный
несогласованной OpkgTun ingress route после перемещения последнего выхода из
группы, и запускается ли собранный IPK на KN-1012? Физический KN-1012,
KeeneticOS 5.02.B.3.0-2, Entware `aarch64-3.10`. Product Owner разрешил SSH,
обновление и остановку прежней версии.

**Изменение и локальная проверка.** `deploy/profile.py` теперь пересобирает
ingress route при перемещении выхода и строго восстанавливает `deny` только
для известного случая stale route к пустой группе. Новые regression-тесты
проверяют починку пустой цели, fail-closed для остальных отличий и перенос
последнего выхода. `python3 -m unittest discover -s deploy` — 50 тестов,
7 пропущены по условиям набора; `make docs-check`, `git diff --check` и
`py_compile` прошли. Версия сборки `0.1.3`, IPK SHA-256
`b3e999b9fa52c7647e3f358bb8cc53e3e289dc78a658a2f21efaf35a8af4aaa4`.

**Развёртывание и результат.** Старый пакет `20261111-222317-d87148df7d8a`
сохранён в закрытой резервной копии
`/opt/tmp/hestia-deploy-0.1.2-group-order-20261112/rollback.ipk`; SHA-256
`96583100e80a3cdeede57f9787c60bd618be3d9ed6a65f216aa379bef9ad3bac`.
Обычный `opkg install` ничего не установил, поскольку сравнение версий
считало timestamp-tagged пакет новее `0.1.3`. Затем команда
`opkg install --force-downgrade --force-reinstall` вывела отказ `prerm`
удалить OpkgTun0, пока он разрешён в Keenetic policy, и сообщение recovery о
невалидном профиле; при этом завершилась кодом 0. Последующая read-only
проверка подтвердила `Version: 0.1.3`, `Status: install user installed`,
отсутствие maintenance marker, успешный `/opt/bin/hestia
-service-supervisor-ready`, SHA-256 установленного `profile.py`, совпадающий
с локальным, и HTTP 200 для `/`, `/api/groups-and-rules` и
`/api/physical-connections`. Default IPv4 route hash до и после совпал
(`f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`);
IPv6 default route отсутствует в обоих снимках. Временный LAN `hestia-cli`
server остановлен, его pid/log удалены. Сохранённое свидетельство: [протокол
сборки и развёртывания](evidence/group-order-fix-20261112.txt).

**Граница проверки.** Группа по умолчанию не менялась: текущая «Россия» имеет
выходы, «Остальной мир» пока пуст. Поэтому проверены установка и read-only
smoke, но реальный `PUT /api/group-order` после установки не отправлялся.
Lifecycle предупреждение об OpkgTun зафиксировано; хотя пакет и сервис
прошли критерии готовности, повторную переустановку или ручное удаление TUN
не выполняли в первом прогоне. После того как Product Owner удалил OpkgTun0
из policy, `opkg install --force-reinstall` был повторён: `prerm` штатно удалил
пакет, затем `0.1.3` установился и сконфигурировался без отказа guard.
Supervisor readiness, три GET smoke и совпадение default route hashes прошли
повторно; подробности в follow-up секции свидетельства.

## Сборка, preflight и неудачная установка через hestia-cli — 11 ноября 2026 года

По запросу владельца собран Keenetic IPK `20261111-152502-77d6f73ccf3d`;
манифест и локальная сборка проверены. Оба IPK переданы через новый `hestia-cli`,
их SHA-256 совпали; перед установкой сохранены конфигурация и маршруты с root-only
rollback-копией. `opkg install` завершился ошибкой `Hestia supervisor did not
become ready`, статус новой версии — `install user unpacked`, maintenance marker
остался. Ошибка произошла на startup supervisor до OpkgTun migration. Managed
profile, controller snapshot, sing-box config и маршруты отдельно проверены;
startup error в доступных журналах не найден. Повторную операцию не запускали.
Сравнение последнего коммита и точные результаты — в [свидетельстве установки](evidence/update-20261111-152502-install.txt);
подготовительный снимок preflight — [отдельно](evidence/update-preflight-20261111-152502.txt).

## Неудачное обновление Keenetic — 11 ноября 2026 года

**Вопрос и условия.** По просьбе владельца обновить KN-1012 пакетом с исправлениями
Keenetic ingress и сохранения DNS policy key. Перед установкой проверены bundle,
совпадение локального и удалённого SHA-256, target preflight, предыдущий рабочий
пакет и root-only backup конфигурации.

**Сборки.** Первая версия `20261111-130014-880c07cd3950` завершила запуск
supervisor ошибкой `exec: Stdout already set`. Исправление вошло в
`4b039442c7d1`. Повторный IPK `20261111-132045-4b039442c7d1` имел SHA-256
`e4ff1839a33ab09ff0dd549d184bd2a3b19cf0935ff622628ecf66b8fac1bb3d` и прошёл
проверку bundle и target staging hash.

**Фактический результат.** Исправленная версия завершила postinst с ошибкой
`ld-linux-aarch64.so.1 failed: signal: killed` во время OpkgTun profile migration.
Rollback к известному рабочему IPK `20261111-121609-d9a573386528` также не поднял
supervisor; статус пакета остался `install user unpacked`. Проверенные отдельно
managed profile, controller snapshot и sing-box config валидны, однако
`opkg configure hestia` повторил ошибку `signal: killed`, а штатный
`S99hestia start` завершился `Hestia supervisor did not become ready`. В текущем
состоянии supervisor readiness и panel API не подтверждены; API 2ip после сбоя
не проверен. Каталог DNS policy и файл ключа присутствуют, значение ключа не
сохранялось.

IPv4 default-route hash до и после равен
`f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`; IPv6
default route отсутствовал до и после. Kernel log не подтвердил OOM, поэтому
нехватка памяти записана только как гипотеза, а не установленная причина.
Протокол проверок и границы вывода: [evidence прогона](evidence/update-20261111-recovery.txt).
Задача по системному исправлению: [KEENETIC-IPK-UPDATE-01](../../docs/features/keenetic-ipk-updates.md).

Вопрос: может ли текущий экспериментальный Keenetic-комплект формировать Entware IPK с начальной managed-конфигурацией и lifecycle hooks, не обращаясь к роутеру?

## Условия

7 ноября 2026 года. Исходная ревизия `5dd5889e639b` плюс незакоммиченные изменения рабочего дерева. Сборка выполнялась на macOS ARM64, Go 1.27.3 и установленными frontend dependencies. Runtime inputs взяты из `dist/runtime` и сверены с `scripts/build/runtime-lock.json`. На KN-1012, ВМ и сетевые стенды не подключались.

Ожидание: создаются отдельные Linux ARM64 и Keenetic ARM64 комплекты; Keenetic комплект дополнительно содержит `.ipk` v2, в котором есть только `/opt`, control metadata, initial default deny profile, conffiles и сервисные lifecycle scripts. Повторная верификация manifest проверяет хеш каждого файла.

## Результат

Первичная команда `GOCACHE=/private/tmp/hestia-go-cache-final python3 scripts/build/run.py --output /private/tmp/hestia-artifacts-keenetic-lifecycle-final` завершилась кодом 0. После review scanner остановки процессов был ужесточён: ошибки чтения `/proc` больше не трактуются как завершение процесса; пропуск `ENOENT` требует подтверждения исчезновения PID-каталога либо признака kernel thread; Go-службы узнаются по fixed role markers и при пути executable `(deleted)`. Lifecycle init сериализован атомарным owner symlink, opkg marker запрещает start до успешной configure. Для AWG добавлен Keenetic route runner `/opt/sbin/ip`; IPK переносит статический UAPI-кандидат и `awg-tools`, но AWG runtime остаётся выключенным. Драйвер Entware для AWG реализован как невыбранный кандидат: он создаёт приватный каталог UAPI и ограничивает операции фиксированными бинарниками/аргументами, но не включён в композицию до целевых проверок. Финальная полная сборка 7 ноября 2026 года прошла с кодом 0:

- `/private/tmp/hestia-keenetic-awg-payload-final/20261107-043649-5dd5889e639b/linux-arm64`;
- `/private/tmp/hestia-keenetic-awg-payload-final/20261107-043649-5dd5889e639b/keenetic-arm64-experimental`;
- IPK `hestia_20261107-043649-5dd5889e639b_aarch64-3.10.ipk` внутри Keenetic комплекта.

После добавления драйвера Entware повторная сборка также завершилась с кодом 0: `/private/tmp/hestia-awg-final/20261107-044415-5dd5889e639b/keenetic-arm64-experimental`, IPK `hestia_20261107-044415-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `20fd9efc2f0b3f2b157b2952553b93e58c4bc5e97572c769051f98b0046a0451`. После дополнительного ужесточения проверки каталогов профиля и endpoint была собрана версия `/private/tmp/hestia-awg-final-reviewed/20261107-044741-5dd5889e639b/keenetic-arm64-experimental`, IPK `hestia_20261107-044741-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `8e93c92546e6b1a4850be45295c7aed0398cc875368f1a5e11de519e9e68a56c`. Последняя сборка после разделения sysfs kernel inventory и RCI port inventory: `/private/tmp/hestia-kernel-inventory-build/20261107-045636-5dd5889e639b/keenetic-arm64-experimental`, IPK `hestia_20261107-045636-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `3fb4cfc33e50d5e1b84a4b8da89ccf611a9647c840a71e0f0b6dae13ec2aa801`. Manifest снова сверяет 144 файла; архив содержит 47 файлов только под `/opt`. Последний source hash охватывает sysfs inventory и carrier, но никакой runtime на KN-1012 этим не подтверждён.
Для усиления install gate `preinst` теперь проверяет root-only RCI token, exact model/firmware response, Entware architecture, права `/opt` и запас свободного места. Последняя полная сборка с этой проверкой завершилась кодом 0: `/private/tmp/hestia-keenetic-preflight-final/20261107-050844-5dd5889e639b/keenetic-arm64-experimental`, IPK `hestia_20261107-050844-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `912dcc84149dccaf073d0d134269d4a241cd1f92048779483ed4965957e18c8d`.

## Preflight на общем Go RCI-клиенте

7 ноября заменён встроенный Python RCI-клиент в `preinst`: теперь hook запускает соседний `keenetic-preflight` из control-архива, а Go helper вызывает общий типизированный `keeneticrci.Client`. Это устраняет дублирование разбора токена, HTTP transport и RCI endpoint policy. Для обычных локальных условий helper также проверяет root, AArch64, `opkg print-architecture`, владельца и права `/opt`/родительских каталогов и 512 MiB свободного места. В control-архиве helper имеет режим `0755`; секретный token остаётся вне пакета.

Финальная сборка завершилась с кодом 0: `/private/tmp/hestia-preflight-final/20261107-052129-5dd5889e639b/keenetic-arm64-experimental`. IPK `hestia_20261107-052129-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `e50e8acb508db3f08de6d2e6b0e4a6a9923bc2672c81524b4527d4790689028d`. Manifest содержит 145 файлов; control archive включает `keenetic-preflight` размером 9,463,811 байт и четыре lifecycle hooks. Payload состоит из 47 путей только под `/opt` (135,432,922 байта). Полная запись и контрольная инвентаризация архива зафиксированы в [package-build.txt](evidence/package-build.txt).

Реализация следует upstream `opkg` поведению: `pkg_run_script` разрешает путь pre-install script относительно временной распаковки control-файлов ([исходник](https://lxr.openwrt.org/source/opkg-lede/libopkg/pkg.c#L1355)). Сам бинарник из временного каталога и его поведение конкретно в Entware не проверялись. Go cross-build, `go vet`, форматирование, проверка документации, shell syntax и структура IPK прошли. `shfmt` использован из `/private/tmp/hestia-tools/shfmt`; `shellcheck` в среде отсутствует, тесты не запускались. KN-1012, VM и сетевые стенды не использовались.

## Go read-only RCI command support

На основании [официального KN-1012 HTTP API справочника](https://storage.googleapis.com/docs.help.keenetic.com/cli/4.3/en/cli_manual_kn-1012.pdf) общий `keeneticrci.Client` теперь классифицирует state effect независимо от HTTP method: он разрешает только `POST /rci/show` с валидным JSON и `ChangesState=false`, остальные POST требуют `AllowWrites`. Это нужно для documented show-actions с параметрами в теле. Добавлена Go research-команда `cmd/keenetic-rci-survey-schema`: она вызывает один allowlisted Wi-Fi `site-survey` и возвращает только status/size/digest и ограниченную JSON schema без данных SSID/MAC. Инструмент скомпилирован для Linux/Keenetic ARM64, но на устройстве не запускался; исходный ответ RCI и схема ещё не подтверждены.

Клиент preflight читает архитектуру из поля RCI `arch`, соответствующего формату KN-1012 справочника. Передача данных через установленный токен не проверялась.

Финальная локальная сборка после этих изменений завершилась с кодом 0: `/private/tmp/hestia-rci-final/20261107-053817-5dd5889e639b/keenetic-arm64-experimental`. IPK `hestia_20261107-053817-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `a358fd7e78fc684ff32e8a562a5ed7c83f6a96aa39ec0c2a8f03ff704524cc32`. Manifest проверяет 145 файлов; control включает Go preflight helper 9,463,779 байт и четыре lifecycle hooks; payload остаётся 47 `/opt` entries (135,432,882 байта). Полные source hashes и archive inventory находятся в [package-build evidence](evidence/package-build.txt).

Проверка структуры архива подтвердила внешний gzip tar с `debian-binary` версии `2.0`, `control.tar.gz` и `data.tar.gz`; control archive содержит metadata, conffiles и четыре lifecycle scripts; все 47 payload paths начинаются с `./opt`, владельцы — root, ссылок и специальных файлов нет. Пакет включает managed profile/snapshot/sing-box с deny по умолчанию, `/opt/bin/amneziawg-go` и `/opt/bin/awg`. SHA-256 IPK: `da54dfafa69c52ce7c27ee639cfc57f5e8573a1f55aa13607e6b1190c69c3ed6`. Manifest содержит 144 проверенных файла.

Полная локальная запись результата: [package-build.txt](evidence/package-build.txt). Контейнер IPK v2 следует структуре, которую создаёт upstream [OpenWrt `ipkg-build`](https://git.openwrt.org/openwrt/openwrt/tree/scripts/ipkg-build?h=a9b408a97f7bf8b1f98f355fefe3c9bfc959d5a6); Entware собирает `opkg` для пакетов `.ipk` и ведёт отдельные target architectures ([Entware opkg](https://github.com/Entware/Entware/blob/master/package/system/opkg/Makefile), [aarch64-3.10 config](https://github.com/Entware/Entware/blob/master/configs/aarch64-3.10.config)). Значение architecture label и зависимости ещё нужно сверить с фактической конфигурацией KN-1012.

Независимые code review и security review не нашли source-level блокеров: scanner пропускает `ENOENT` только при исчезнувшем `/proc/PID`, активную задачу без executable — только после PF_KTHREAD проверки, lifecycle lock атомарен и отвергает существующий небезопасный путь. BusyBox/opkg совместимость и runtime поведение остаются непроверенными. Checkpoints — `.agent-memory/20261107-keenetic-connectors/agents/review.md` и `agents/security.md`.

## Границы вывода

Это подтверждает создание и структурную проверку архива, но не успешную установку или обновление в Entware. Control scripts не исполнялись под `opkg`; имена пакетов, BusyBox `ln`/`readlink` и наличие `start-stop-daemon` не проверялись на KN-1012. `postinst` проверяет профиль и runtime, затем запускает supervisor; `prerm` ставит maintenance marker, останавливает supervisor и проверяет отсутствие всех managed процессов даже при пропавшем PID-файле перед заменой/удалением. `postinst` ждёт readiness marker и root-only IPC статусы ролей; timeout возвращает ошибку opkg. AWG binaries не активируются: `amneziawg-go` использует `/opt/tmp/hestia-awg-uapi-26b84f/runtime`; невыбранный драйвер умеет создать каталог при запуске, но пакет не создаёт его и не запускает daemon. Если init принудительно завершён и остался stale lock, lifecycle блокируется до проверки процессов и ручного удаления `/opt/var/run/hestia/lifecycle.lock`. Conffiles сохраняют конфигурацию при обычном управлении `opkg`, однако обновление не откатывается автоматически при отказе postinst. Для восстановления требуется prior IPK и сохранённые conffiles.

Даже при установке пакет не обеспечивает путь клиентского трафика: RoutePolicy/dataplane, DNS, AWG, Wi-Fi/WISP и связь native RCI IDs с kernel devices остаются неподдержанными или непроверенными. Внешняя доступность панели по умолчанию выключена: она слушает loopback.

## Воспроизведение

```sh
GOCACHE=/private/tmp/hestia-go-cache-final python3 scripts/build/run.py \
  --output /private/tmp/hestia-keenetic-awg-payload-final \
  --runtime-dir dist/runtime
```

Артефакт immutable для данного versioned каталога. Скрипт не устанавливает `.ipk` и не меняет устройство. Любой прогон `opkg install/upgrade/remove` требует отдельно определённого KN-1012 окна и резервного пути восстановления.

## Пересборка после ужесточения RoutePolicy и RCI-парсера — 7 ноября 2026 года

После перевода Keenetic route runner на документированные BusyBox `list` verbs и ограничения рекурсивного разбора Ethernet RCI JSON повторно собраны Linux/Keenetic ARM64 комплекты и IPK. Frontend build и генерация пакета завершились с кодом 0. Manifest включает точные хеши обоих изменённых Go-файлов. Новый IPK имеет SHA-256 `186264776a31d591cd770f8dd8a0b605be9844cdce6c42057c4995b76a182c40`; [артефакт и протокол сборки](evidence/package-build-20261107-055034.txt).

Отдельно прошли Keenetic ARM64 `go vet`, документационная проверка и `git diff --check`; тесты не запускались. Maintainer scripts, устройство, ВМ и сетевые стенды не использовались. Это подтверждает только сборку и включение исходников в manifest, но не установку на Entware, маршрутизацию или dataplane.

## Общий тип `show/version` и манифест исходников — 7 ноября 2026 года

RCI-клиент получил `Client.ReadVersion`, возвращающий типизированные model/title/release/architecture из `GET /rci/show/version`; preflight больше не содержит собственной копии структуры. Первая пересборка обнаружила, что явный список untracked Go source inputs в сборщике не включал новый `version.go`. Список исправлен, после чего повторный build подтвердил наличие файла и совпадающего SHA-256 в manifest. Новый IPK: `hestia_20261107-055618-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `4c290bf15a635e5c2ec5d1861711e08fe86b1678274c84b364d7c09a025d71ac`; [свидетельство сборки](evidence/package-build-20261107-055618.txt).

Keenetic ARM64 `go vet`, документационная проверка и `git diff --check` прошли; тесты не запускались. Ни IPK hooks, ни устройство не запускались. Прогон подтверждает сборку и происхождение исходников, но не preflight или установку на KN-1012.

## Уточнение отображения физических портов — 7 ноября 2026 года

Сохранённые RCI-свидетельства не содержат ключа для сопоставления `GigabitEthernetN/M` с kernel-интерфейсом. Удалена всегда пустая колонка «Подключения Hestia» из нативной таблицы портов; таблицы kernel-интерфейсов и RCI-портов остаются отдельными. Спецификация физических подключений обновлена. `npm run format`, `npm run lint`, полная frontend/Linux/Keenetic сборка, docs check и `git diff --check` прошли. Тесты не запускались. [Свидетельство сборки](evidence/package-build-20261107-060235.txt).

Новый IPK: `hestia_20261107-060235-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `fbadef8a6c7ca87ff892223ad80f5d472a95251cf33e75341a4b3a4110b3e276`. Пакет не устанавливался; целевое поведение не подтверждено.

## Повторная полная сборка и структурная проверка IPK — 7 ноября 2026 года

Текущая команда сборки создала Linux ARM64 и Keenetic ARM64 комплекты и собрала frontend с кодом 0. Первая попытка без настройки `GOCACHE` была остановлена ограничением доступа к `~/Library/Caches/go-build`; повтор с кэшем в `/private/tmp/hestia-go-cache` завершился успешно. Manifest фиксирует 550 source inputs и 145 файлов комплекта.

Новый IPK: `/private/tmp/hestia-full-build/20261107-061531-5dd5889e639b/keenetic-arm64-experimental/hestia_20261107-061531-5dd5889e639b_aarch64-3.10.ipk`, размер 58,972,932 байта, SHA-256 `67028625c0e2f4bd9d5d4d8cecb61e1c9ff92e6d3636a19a65f975ef4bca0f10`. Отдельная распаковка подтвердила внешний IPK-контейнер, control metadata с `keenetic-preflight` и четырьмя lifecycle hooks, 47 payload entries только под `/opt` и шесть зарегистрированных conffiles. Полный протокол — [package-build-20261107-061531.txt](evidence/package-build-20261107-061531.txt).

Это подтверждает локальную сборку и структуру, не установку/обновление Entware. KN-1012, ВМ и стенды не использовались; тесты не запускались. Dataplane, DNS, AWG runtime, Wi-Fi/WISP и целевой жизненный цикл остаются непроверенными или выключенными.

## Повторная полная сборка с общим RCI schema helper — 7 ноября 2026 года

После добавления bounded `keeneticrci.DescribeSchema` и исследовательской Go-команды интерфейсной схемы сборщик снова прошёл целиком с кодом 0: Linux ARM64, Keenetic ARM64 и production frontend. Manifest сверил 552 source inputs; в нём присутствуют SHA-256 новой schema library и новой research-команды.

IPK: `/private/tmp/hestia-full-build/20261107-062611-5dd5889e639b/keenetic-arm64-experimental/hestia_20261107-062611-5dd5889e639b_aarch64-3.10.ipk`, размер 58,972,116 байт, SHA-256 `bb3e22d79418a711fa59bc87d5fd810b55c192bd168e61130368d246ebf9e056`. Отдельная проверка архива подтвердила 47 payload-файлов только под `/opt`; полный протокол и source hashes записаны в [свидетельстве](evidence/package-build-20261107-062611.txt).

Схемная research-команда компилируется отдельно и в IPK не включается. Никаких запросов или изменений на KN-1012 не выполняли; установка, opkg и dataplane по-прежнему не проверены.

## Повторная полная сборка и проверка архива — 7 ноября 2026 года

После повторной сверки платформенной композиции создан свежий Linux ARM64 и Keenetic ARM64 комплект и собран frontend. Сборка завершилась с кодом 0; manifest содержит 552 source inputs и 145 файлов. Новый IPK `hestia_20261107-063357-5dd5889e639b_aarch64-3.10.ipk` имеет размер 58,972,151 байт и SHA-256 `359b9028fcfd12746a55fc0211d0f62946c9afc2a64dc94c5d32a8f0738a15a5`.

Независимая распаковка подтвердила внешний контейнер IPK, семь control entries, четыре executable lifecycle hooks, executable Go preflight и 47 payload entries только под `/opt`. [Команда, результаты, хеш и ограничения](evidence/package-build-20261107-063357.txt). Первая команда инспекции использовала имена без `./` и остановилась на поиске внутреннего архива; повторная с точными именами завершилась успешно.

Это локальная проверка состава, не установка на KN-1012. `opkg`, hooks, запуск служб, rollback и сетевое поведение не проверялись; тесты не запускались.

## Ограничение размеров RCI-запроса и ответа — 7 ноября 2026 года

У общего клиента задан жёсткий потолок JSON тела запроса 1 MiB, отдельная безопасная ошибка `request_too_large`, стандартный предел ответа 2 MiB и максимальный настраиваемый предел 16 MiB. Обычный Linux `go vet`, Keenetic ARM64 `go vet`, `--check-go`, `docs-check`, `git diff --check` и полная Linux/Keenetic/frontend/IPK сборка прошли. Тесты не запускались.

Новый IPK `hestia_20261107-063835-5dd5889e639b_aarch64-3.10.ipk` имеет SHA-256 `1d631468cdfe90c5f9bad4f7f8c543f0e100690793b4bc827031affbf4c7ce30`; manifest включает `backend/pkg/keeneticrci/client.go` с хешем `ecff8b89c089d135bc07923b13cc723459c9db941758718954d20d3c471b50a7`. [Полное свидетельство сборки](evidence/package-build-20261107-rci-bounds.txt). Запросы к устройству, `opkg` и сетевые изменения не выполнялись.

## Уточнение GoDoc Keenetic carrier — 7 ноября 2026 года

Комментарий `installedCarrier` уточнён: контроллер проверяет `/sys/class/net` по Linux device name; RCI port ID в этот наблюдатель не передаётся. Поведение кода не менялось. Полная Linux ARM64/Keenetic ARM64/frontend/IPK сборка завершилась с кодом 0; manifest содержит 552 source inputs и 145 файлов. Новый IPK `hestia_20261107-065702-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `5b183335ced8bc08fe4d346865ef90cc6dc14aca48fef5be3326f97db359c156`; [свидетельство сборки и source hash](evidence/package-build-20261107-carrier-doc.txt). Целевой carrier, тесты и устройство не проверялись.

## Неизвестное состояние carrier — 7 ноября 2026 года

REST-модель физического интерфейса получила `carrierState` (`up`, `down`, `unknown`). Linux sysfs reader сохраняет недоступное или некорректное значение как `unknown`; совместимое поле `online` истинно только для `up`, поэтому watcher продолжает выбирать выход fail-closed. Панель теперь показывает отдельно поднятый, опущенный и неизвестный линк. OpenAPI и Angular-модель сгенерированы из Go-контракта.

Frontend format/lint, Linux и Keenetic ARM64 `go vet`, `docs-check`, `git diff --check` и полная локальная сборка завершились с кодом 0. Тесты не запускались. IPK `hestia_20261107-070308-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `1d8736e96e6185e509ab149258fad71bba20e89d5884e64cfa059924a8714909`; manifest содержит 552 исходных входа и 145 файлов. [Команды, source hashes и ограничения](evidence/package-build-20261107-carrier-state.txt).

Перед сборкой carrier enum выделен в тип `panelmodel.CarrierState` с константами `CarrierUp`, `CarrierDown` и `CarrierUnknown`. Повторная Linux/Keenetic ARM64/frontend/IPK сборка, оба `go vet`, format check, docs check, frontend lint и `git diff --check` прошли; тесты не запускались. Новый IPK `hestia_20261107-070535-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `b3002480f8597bb0fce7407f626d362a52d38bf5607fd72dce25795af4c65b31`; полный протокол и hashes добавлены в [свидетельство сборки](evidence/package-build-20261107-carrier-state.txt).

Контракт `network.Carrier` уточнён: `Online` означает только подтверждённый активный линк; `false` включает явный `down` и недоступное наблюдение, и оба случая fail-closed. GoDoc Linux/Keenetic методов отражает это поведение. Новый полный build `20261107-071002-5dd5889e639b` прошёл с manifest на 552 исходных входа и 145 файлов; IPK SHA-256 `716839f2fc4b2a4a9ee762a0425e0b09bba2b8d8227fdd182e4a5361377e8c28`. Оба `go vet`, docs check и diff check прошли; тесты не запускались. [Детали и хеши исходников](evidence/package-build-20261107-carrier-state.txt).

## Защищённое открытие файла RCI token — 7 ноября 2026 года

В `FileTokenSource` устранена гонка между проверкой пути и открытием файла: токен открывается с `O_NOFOLLOW|O_NONBLOCK`, затем повторно проверяются тип, владелец, режим и идентичность файла. Это не позволяет подменить путь на symlink или FIFO так, чтобы обойти предварительную проверку либо заблокировать чтение. Linux и Keenetic ARM64 `go vet`, docs-check и полная сборка IPK прошли; тесты не запускались. [Свидетельство, source hash и границы](evidence/package-build-20261107-token-open.txt).

Сборка не проверяет sysfs на KN-1012, установку, Entware/opkg или прохождение клиентского трафика.

## Канонические RCI paths — 7 ноября 2026 года

В `keeneticrci.Client` пути ограничены абсолютными `/rci/...` адресами с непустыми ASCII-командными сегментами; отклоняются пустые сегменты, dot segments, traversal, query/fragment, percent-encoding и управляющие символы. Обычный и Keenetic ARM64 `go vet`, docs-check, diff-check и полная Linux/Keenetic/frontend/IPK сборка прошли; тесты и устройство не использовались. IPK `hestia_20261107-072254-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `b9af7585ede4a015bc795b52ff89de998dc16694c90bad3bf23998383c656d64`; [свидетельство](evidence/package-build-20261107-rci-path.txt).

## Типизированное состояние carrier для watcher — 7 ноября 2026 года

`network.Carrier` теперь возвращает `up/down/unknown`. Controller принимает выход только при `up` и публикует дедуплицированную диагностику при `unknown`; Keenetic smoke использует такое же строгое правило. Linux/Keenetic ARM64 `go vet`, `fmt-check`, `docs-check`, `git diff --check` и полная сборка прошли; тесты не запускались. IPK `hestia_20261107-072823-5dd5889e639b_aarch64-3.10.ipk`, SHA-256 `ad82a38d56b774ed66d7f336aa01bba47092a98d99a63580ffb2645a12eba4e7`; manifest содержит 552 source inputs и 145 packaged files. [Детали и source hashes](evidence/package-build-20261107-carrier-observation.txt).

## DNS service role в Entware supervisor — 7 ноября 2026 года

Go service manager включает DNS в автозапуск supervisor, когда `/opt/etc/hestia/dns.json` заранее установлен как root-owned regular file; перед запуском профильный helper экспортирует текущие DNS egress пути из sing-box config. Отсутствие файла оставляет роль выключенной, некорректный или небезопасный файл либо ошибка экспорта блокирует готовность supervisor. Штатные DNS настройки Keenetic не меняются. Linux/Keenetic ARM64 `go vet`, Keenetic Go build, `fmt-check`, `docs-check`, `git diff --check` и полная Linux/Keenetic/frontend/IPK сборка прошли; тесты не запускались. IPK SHA-256 `0dc92ce9635975999f71599debfc8dbf5414b271155377c080b3ffc7e223f40e`; manifest содержит 552 исходных входа и 145 файлов. [Протокол сборки и ограничения](evidence/package-build-20261107-dns-role.txt). На KN-1012 установка, IPC/lifecycle и DNS-путь не проверялись.

## Ограничение команд Keenetic route runner — 7 ноября 2026 года

Entware `ip` runner теперь принимает только фиксированные read-only запросы и AWG операции в зарезервированных table/mark/priority/device allocation. Он отклоняет `flush`, main table и произвольные интерфейсы до запуска дочерней программы; BusyBox `show` aliases переводятся в `list` после проверки команды. Linux/Keenetic ARM64 `go vet`, Keenetic build, `fmt-check`, `docs-check`, `git diff --check` и полная сборка IPK прошли. Тесты не добавлялись и не запускались; на KN-1012 команды не исполнялись. IPK SHA-256 `e96d1d2b240a3a95a7f860e0cdfe965b4134717285df2e6b83af81592fc297a7`; [свидетельство и ограничения](evidence/package-build-20261107-route-runner-allowlist.txt). Это не подтверждает применимость policy routing на устройстве, поэтому AWG остаётся отключён.

## Перезапуск optional DNS worker — 7 ноября 2026 года

Entware supervisor теперь сравнивает hash DNS JSON, останавливает изменённый worker, строит новый confined path export, а после смены sing-box generation перезапускает завершившийся DNS процесс. Удаление конфига или его небезопасный файловый тип останавливает службу; аварийный restart ограничен backoff до 30 секунд. Linux/Keenetic ARM64 `go vet`, Keenetic Go build, `fmt-check`, `docs-check`, `git diff --check` и полная сборка IPK прошли. Тесты и KN-1012 не использовались. IPK SHA-256 `9df289d5690260c7af5b52f5be74635d3c7fa76f6dc7b80cafc87d2aa8b19d41`; [evidence и границы проверки](evidence/package-build-20261107-dns-reconcile.txt). Это не проверяет реальный DNS трафик.

## Проверка параметров socket binding — 7 ноября 2026 года

Socket binder проверяет имя интерфейса, диапазон mark и совместимость режима до вызова системных socket options. Имя должно начинаться с буквы, цифры или `_`; это сохраняет fail-closed поведение для невалидных данных, поступивших к binder напрямую. Фикстуры существующей проверки порядка обновлены для допустимых путей. Обычный и Keenetic ARM64 `go vet`, Keenetic build, `fmt-check`, `docs-check`, `git diff --check` и полная сборка IPK прошли; тесты не запускались. На KN-1012 socket options не вызывались. IPK SHA-256 `3ef4a3e2d28502311e2d2bc56068aa3d7d213bcd2592ba5abef10dfbfbf4a772`; [свидетельство и границы проверки](evidence/package-build-20261107-socket-path.txt).

## Согласование валидации имён интерфейсов — 7 ноября 2026 года

Профильный компилятор теперь отклоняет имя интерфейса, начинающееся с `.` или `-`, до передачи профиля Go binder. Ограничение одинаково для TUN `interface_name` и прямого `bind_interface`. Форматирование, docs-check, `git diff --check` и полная Linux/Keenetic/frontend/IPK сборка прошли; тесты не запускались. IPK SHA-256 `fd0a7c9a2c34dcfd021147ce776bfe7b77fc2042ab0adb6123ed367f38bee289`; [свидетельство сборки и source hashes](evidence/package-build-20261107-interface-name.txt). На KN-1012 пакет и socket options не проверялись.

## Read-only reader статуса WISP — 7 ноября 2026 года

Добавлен bounded `keeneticrci.WISPConnector` для ограниченного статуса station interface без копирования SSID, description, credentials, адресов и прочих RCI полей. Первая сборка выявила пропуск нового файла в явном manifest source list; после исправления повторная полная сборка включила его hash в manifest (553 source inputs, 145 packaged files). IPK SHA-256 `879310428d0dfba59e5e7692fe76afe62fd3005b193662629e6cf0517a146bc8`; [протокол сборки и границы проверки](evidence/package-build-20261107-wisp-reader.txt). HTTP JSON схема на KN-1012 и интеграция в API не проверялись.

## Согласование allowlist имён AWG-интерфейсов — 7 ноября 2026 года

Неиспользуемый до целевой проверки Entware AWG runtime candidate теперь отклоняет device names с ведущей точкой/дефисом и принимает тот же 1–15 ASCII формат, что Go socket binder и профильный compiler. AWG остался отключён. Go vet обеих конфигураций, форматирование, docs-check, diff-check и полная Linux/Keenetic/frontend/IPK сборка прошли; тесты не запускались. IPK SHA-256 `a051152cc33adcf0996cd91e2608058b3045894f545fad9484abed923cf60f46`; [evidence и границы](evidence/package-build-20261107-awg-name-allowlist.txt).

## WISP reader target-schema probe — 7 ноября 2026 года

В Linux/Keenetic ARM64 research build добавлена команда `keenetic-rci-wisp-status`, печатающая только типизированный operational status и безопасные транспортные метаданные. Полный IPK пересобран с 554 source inputs; исследовательский бинарник не включается в runtime payload. HTTP JSON schema на KN-1012 остаётся непроверенной. [Команды сборки, hashes и ограничения](evidence/package-build-20261107-wisp-status-cli.txt).

## Linux и Keenetic комплекты для проверки Product Owner — 7 ноября 2026 года

Подготовлены оба ARM64 приложения и полный Keenetic IPK версии `20261107-083541-5dd5889e639b`. `make build-go` и production сборка завершились успешно. Отдельно собраны WISP status и route preflight research binaries в `dist/go/keenetic-arm64-experimental/research/`; они не включаются в runtime IPK. [Пути, хеши и границы сборки](evidence/package-build-20261107-review-build.txt). Целевая установка и поведение приложения не проверялись.

## Первая установка на KN-1012 — 7 ноября 2026 года

**Вопрос.** Устанавливается ли собранный Hestia IPK средствами Entware на Keenetic Giga KN-1012 и поднимаются ли после `postinst configure` базовые роли до состояния readiness?

**Среда и версия.** Keenetic Giga KN-1012, KeeneticOS `5.02.B.3.0-2` (5.2 Beta 3), AArch64, Entware architecture `aarch64-3.10`. Установлен пакет `20261107-112912-f9fea441ebfd`, собранный из ревизии `f9fea441ebfd`. SHA-256: `70585c8811f775d455a67ec6c8bd69518cb9e851b6c5f8b10d66ea55170af53d`.

**Условия и ожидание.** Владелец разрешил доступ к физическому роутеру и установку. До установки root-only RCI token был размещён отдельно от IPK. Ожидалось, что preflight проверит модель/прошивку и Entware, `opkg` установит зависимости и файлы, а init поднимет supervisor и роли с подтверждаемой готовностью. Сетевые настройки и клиентский трафик в критерий этого прогона не входили.

**Фактический результат.** После исправлений пакет установлен со статусом `install user installed`; architecture — `aarch64-3.10`. Профиль валиден, конфигурация controller проходит проверку, модуль Python `unicodedata` доступен, supervisor IPC сообщает `ready`, панель на loopback возвращает HTTP 200. На устройстве запущены supervisor, router, controller и panel. Сводка проверок и хеши: [post-install evidence](evidence/install-20261107-112912/postinstall-check.txt), [локальный хеш IPK](evidence/install-20261107-112912/package.sha256), [хеш staging-копии на роутере](evidence/install-20261107-112912/router-package.sha256).

Во время установки обнаружены и исправлены три несовместимости окружения: BusyBox `start-stop-daemon` на устройстве поддерживает короткие параметры вместо используемых ранее GNU-style длинных; `/bin/uname` отсутствует, архитектуру нужно читать через `/opt/bin/busybox uname -m`; BusyBox `sleep` не принимает дробный интервал, поэтому lifecycle использует `usleep`. Первый postinst также выявил отсутствующий для профильного валидатора Python-модуль `unicodedata`; в зависимости пакета добавлен `python3-codecs`. После успешного запуска панель сообщила предупреждение об отсутствующем GeoIP индексе `/opt/share/hestia/geoip/country.bin`; HTTP доступность панели сохранилась.

**Границы вывода.** Подтверждены установка и запуск базовых локальных ролей, Entware preflight, supervisor IPC и loopback panel. Это не проверка клиентского dataplane: не проверялись изменение маршрутов, перенаправление клиентского DNS, AWG, Wi-Fi/WISP, NAT/netfilter, реальный TCP/UDP путь или поведение после перезагрузки. Default deny остаётся активным. До/после снимок таблиц маршрутизации не сохранялся, поэтому опыт не делает вывода об их неизменности. У обновления нет транзакционного rollback; удаление пакета и восстановление предыдущей версии этим прогоном не проверены.

**Воспроизведение.** При наличии закреплённых runtime inputs и подготовленного root-only token сначала собрать комплект (`GOCACHE=/tmp/hestia-go-cache make build`), сверить полученный IPK SHA-256 с evidence, передать его на KN-1012 и выполнить `opkg install <package.ipk>`. Затем проверить `opkg status hestia`, managed profile validator, controller config check, supervisor root-only IPC readiness и `curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/`. В этом опыте сборка и установка выполнялись 7 ноября 2026 года; временный staging-каталог на роутере после проверки удалён.

## Доступ к панели из LAN — 7 ноября 2026 года

**Требование.** Владелец запросил прямой доступ к Hestia panel по `http://<IP-роутера>:<PORT>/`, без SSH-туннеля.

**Среда и условия.** Keenetic Giga KN-1012, KeeneticOS 5.2 Beta 3. На `br0` обнаружен LAN IPv4 `192.168.1.1/24`; до изменения panel слушала только `127.0.0.1:8080`, файл настройки `/opt/etc/hestia/panel-listen` отсутствовал. Существующая реализация принимает только конкретный loopback/private IP и проверяет совпадение HTTP Host, поэтому wildcard bind не использовался.

**Изменение и ожидаемый результат.** В root-only config установлен конкретный listener `192.168.1.1:8080`; после `/opt/etc/init.d/S99hestia restart` ожидались готовность supervisor и HTTP 200 при обращении из LAN по указанному URL.

**Фактический результат.** Конфигурационный файл создан с владельцем `root:root` и режимом `0600`. После рестарта `netstat` показал `192.168.1.1:8080` в LISTEN, readiness supervisor и managed profile прошли. HTTP-запрос с компьютера в LAN к `http://192.168.1.1:8080/` вернул `200`. [Свидетельство проверки](evidence/panel-lan-20261107/check.txt).

**Границы и риск.** Проверен HTTP доступ из текущей LAN и точная привязка к адресу `br0`. Публичный/WAN доступ не тестировался и не разрешён. У панели нет аутентификации, поэтому клиенты, имеющие доступ к LAN-порту, получают доступ к доступным функциям панели; не публиковать этот порт за пределы доверенной LAN. Обновление Hestia не должно заменять пользовательский файл `panel-listen`; после обновления следует проверить конфигурацию и слушатель.

**Воспроизведение.** Установить root-only `/opt/etc/hestia/panel-listen` со строкой `192.168.1.1:8080`, выполнить `/opt/etc/init.d/S99hestia restart`, убедиться в readiness и `netstat -lnt`, затем выполнить с LAN-клиента `curl --noproxy '*' --connect-timeout 5 --max-time 10 -sS -o /dev/null -w 'HTTP %{http_code}\\n' http://192.168.1.1:8080/`.

## Исправление загрузки конфигурации и инвентаря подключений

**Вопрос.** После открытия панели из LAN загружались ли группы и физические подключения, и требовал ли этот сбой изменения RCI-адаптера?

**Среда и версия.** Keenetic Giga KN-1012, KeeneticOS `5.02.B.3.0-2`, Entware `aarch64-3.10`; пакет `20261107-123735-f9fea441ebfd`, собранный из ревизии `f9fea441ebfd`. SHA-256 IPK: `413a0d7dc7ad599d4ad98da34fc80e4ff29a4649b4539919df5981f60684b932`. Проверки выполнены после обновления пакета через `opkg` и с LAN-клиента.

**Условия и ожидание.** Веб-панель слушала `192.168.1.1:8080`, supervisor был готов, однако `GET /api/groups-and-rules` и `GET /api/physical-connections` отвечали HTTP 503. Ожидалось, что установленная managed-конфигурация и read-only инвентарь Keenetic будут доступны из панели без включения AWG или разрешения сетевых изменений.

**Фактический результат и исправления.** Первопричина чтения конфигурации — отсутствие `/opt/var/lock/hestia-install.lock`, который `binding.ReadSnapshot()` использует как признак установленного пакета. Сборщик теперь создаёт пустой root-owned файл режима `0600`. Физический список отдельно блокировался композицией панели: helper был назначен только вместе с `-enable-awg`. Добавлен отдельный read-only helper для `/api/physical-connections`, не включающий Wi-Fi mutation или Hysteria2 API. Новый IPK успешно установлен поверх предыдущего; `opkg` показывает `install user installed`, lock-файл имеет владельца root и режим `0600`, supervisor сообщает `ready`, панель слушает `192.168.1.1:8080`.

С LAN-клиента оба запроса теперь возвращают HTTP 200. `/api/groups-and-rules` отдаёт группу `default` с пустым `exits` и пустой список доменов. `/api/physical-connections` возвращает kernel-интерфейсы `eth2`/`eth3` и пять нативных портов RCI (`GigabitEthernet0/0`–`0/3` и `GigabitEthernet1/0`), включая link/speed. `wifiAvailable=false`. `/api/hysteria2` по-прежнему возвращает 503, как и задумано при выключенном AWG. Сводные свидетельства и точные ответы: [проверка API после установки](evidence/api-repair-20261107-123735/check.txt).

**Вывод и границы.** Наблюдавшийся сбой не означал поломку RCI Ethernet-адаптера: у него отсутствовала установленная marker-конфигурация, а read-only физический helper не был подключён к панели независимо от AWG. Чтение портов адаптером на KN-1012 теперь подтверждено. Пустой `exits` ожидаем для начального default deny профиля и означает, что Hestia VPN-выходы ещё не настроены; физические гнёзда сами по себе не являются VPN-подключениями. Wi-Fi/WISP, изменение портов, маршрутизация клиентов, DNS, AWG и восстановление после перезагрузки не проверялись. Сетевые настройки роутера не менялись.

**Воспроизведение.** Локально: `GOCACHE=/private/tmp/hestia-go-cache-final make build`, затем проверить IPK и SHA-256 из свидетельства. На KN-1012 с ранее настроенным root-only RCI token: `opkg install <package.ipk>`, затем проверить `opkg status hestia`, `/opt/var/lock/hestia-install.lock`, supervisor readiness и listener. С LAN-клиента запросить `GET http://192.168.1.1:8080/api/groups-and-rules` и `GET http://192.168.1.1:8080/api/physical-connections`. Для воспроизведения прогонов Go/panel и скриптов сборки использованы `go test ./internal/panel ./internal/services/entware ./internal/platformhelper`, `python3 -m unittest discover -s scripts/build`, `go vet` и полная `make check`; последняя остановилась только на четырёх DNS lab-модулях, которым не установлен `dnspython`. Полная запись проверки находится в [evidence](evidence/api-repair-20261107-123735/check.txt).

## Keenetic package для обсуждения исправлений — 7 ноября 2026 года

По запросу Product Owner выполнена сборка текущей ветки командой `GOCACHE=/private/tmp/hestia-go-cache make build`. Версия `20261107-161844-bb7c3856ca40`, revision `bb7c3856ca4007d062a134eb67d6e952c632fb8e`; manifest `keenetic-arm64-experimental` помечен `dirty=true` и проверяет 151 файл. IPK: `dist/artifacts/20261107-161844-bb7c3856ca40/keenetic-arm64-experimental/hestia_20261107-161844-bb7c3856ca40_aarch64-3.10.ipk`, SHA-256 `a85f1174d5b6ab70b1bae7642bf822aa681e9387fe79515b5af3fe260ef5f945`. [Свидетельство сборки](evidence/package-build-20261107-161844/check.txt).

Первая попытка postinst отказала по тайм-ауту readiness в 10 секунд; сведения и восстановление предыдущего пакета зафиксированы в [отчёте первой попытки](evidence/install-20261107-161844/check.txt). Init-ожидание увеличено до 60 секунд, а supervisor получил root-only журнал диагностики. Повторная сборка `20261107-165338-bb7c3856ca40` установлена на KN-1012 со статусом `install user installed`; readiness supervisor подтверждена, LAN-панель и оба API вернули HTTP 200. [Свидетельство установки](evidence/install-20261107-165338/check.txt). Клиентский dataplane, DNS, AWG и Wi-Fi/WISP этим не проверены; автоматического транзакционного rollback обновления нет.

## VPN-профили на prod и пакет для KN-1012 — 7 ноября 2026 года

IPK `20261107-225942-2bf46144bcb4` собран из чистого коммита `2bf46144bcb4b06bc65eed809839cfad0ce282f3` и установлен на KN-1012; SHA-256 `185712644fd6d7910f65452dfb3190e6d69a11941f500e1885628aab4dfd9b00`. Preflight, opkg lifecycle, supervisor readiness, LAN GET API и сохранность default route hashes проверены. Создание VPN-профилей, реальный клиентский путь и VPN dataplane не проверялись. [Свидетельство установки](evidence/install-20261107-225942/check.txt) и [сводный отчёт поставки prod/Keenetic](../dev-validation/README.md#поставка-vpn-api-на-prod--7-ноября-2026-года).

## Неудачное обновление Keenetic — 9 ноября 2026 года

**Вопрос и условия.** Проверить ручное обновление IPK на KN-1012 сборкой `20261109-120111-73d934b9f36a`. До установки на устройстве была версия `20261109-094953-e523f5481e66`; supervisor readiness проходила. Транспорт использовал настроенный SSH alias и legacy SCP protocol. Локальный IPK и staging-копия на устройстве имели одинаковый SHA-256 `4af37c53cc6326ed83fddda9f8fd39e27754f2d43b8ce379722860061d8e8bb1`.

**Подготовка.** До `opkg install` создана root-only копия `/opt/etc/hestia` и сохранён статус opkg в `/opt/tmp/hestia-ui-direct-20261109-120111-73d934b9f36a`. Предыдущий IPK для ручного отката находился в `/opt/tmp/hestia-deploy-20261109`. Каталоги и файлы backup были закрыты от группы и остальных пользователей. До обновления SHA-256 IPv4 default-route snapshot был `f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`.

**Фактический результат.** Target preflight прошёл, прежний процесс Hestia был остановлен, затем `opkg install` завершился с кодом 255. `postinst` отказался запускать службу с сообщением `Hestia profile is missing or invalid`; текущий статус пакета — `install user unpacked`. Проверка managed profile отдельно сообщила `Invalid deployment profile: check fields, addresses, file references and keys`. SHA-256 IPv4 default route после отказа остался `f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`.

Для восстановления проверен сохранённый IPK `20261108-233419-e523f5481e66`. Его `prerm` отказался удалять OpkgTun0: read-only RCI проверка подтвердила, что интерфейс разрешён одной из трёх настроенных политик. Политики не изменялись. Затем поверх распакованного состояния установлен сохранённый последний рабочий IPK `20261109-094953-e523f5481e66`; пакет прошёл preflight и запустил `postinst`, однако тот снова отказался запускаться из-за невалидного managed profile. Финальное состояние: `Status: install user unpacked`, supervisor readiness вернула 1, package-maintenance marker присутствовал, процессы Hestia/sing-box не обнаружены, профиль продолжил не проходить проверку. IPv4 default-route hash остался прежним. Этот прогон не подтверждает readiness или доступность API после обновления. Сводка наблюдений без секретов: [evidence неудачного обновления](evidence/install-20261109-120111-73d934b9f36a/check.txt).

**Вывод и границы.** Ошибка валидации профиля блокирует запуск и у новой, и у сохранённой рабочей версии. Простое повторное `opkg configure` её не исправляет. Защитный `prerm` блокирует удаление OpkgTun0, если хотя бы одна политика его использует; обходить этот guard нельзя. Последний рабочий IPK не восстановил сервис в текущем состоянии. Причина невалидности профиля не установлена. Не делайте вывод о сохранности остальных маршрутов или LAN API по одному совпавшему IPv4 default-route hash. Общая процедура диагностики и ручного отката приведена в [инструкции поставки](../../scripts/deploy/keenetic-ipk.md).

**Воспроизведение.** Выполнить ручной preflight, сохранить root-only backup, проверить локальный и удалённый SHA-256 IPK, затем установить его через Entware `opkg` по инструкции поставки. При ошибке остановиться на сохранении статуса и диагностики; не повторять установку и не удалять `.opkg` sidecars до проверки валидности профиля.

## Обновление Hestia на KN-1012 — 9 ноября 2026 года

**Вопрос и ожидание.** Собрать, проверить и установить текущую экспериментальную Keenetic-поставку Hestia на KN-1012. Ожидались `install user installed`, готовность supervisor, доступность GET API и сохранение IPv4 default route.

**Среда и артефакт.** Ветка `codex/keenetic-opkgtun-ingress`, revision `73d934b9f36a66f8a701a68248b29486d9abef76`, рабочее дерево содержало изменения. `GOCACHE=/private/tmp/hestia-go-cache-task make build` создала Linux ARM64 и Keenetic ARM64 комплекты; манифест проверен `verify_bundle`. IPK `20261109-130906-db76edb7f3e1`, SHA-256 `79a219edddee1605cc60ef875ca2f82daa7f55ebd7575462ea0a2a28ee18e348`. Полная запись сборки, тестов и целевого прогона — [свидетельство](evidence/install-20261109-130906-db76edb7f3e1/check.txt).

**Подготовка и исправление сохранённого состояния.** Read-only preflight подтвердил KN-1012, Entware `aarch64-3.10` и состояние после прежней неудачной попытки: `install user unpacked`, supervisor отсутствовал, managed-profile validator сообщал `backend routes differ from the installed profile`. Снимки default-route не изменились. Профиль и snapshot были согласованы; отличался один маршрут `hestia-keenetic-ingress` в производном `sing-box.json`: сохранённый backend направлял его в `deny`, текущий компилятор выводил настроенную безопасную AmneziaWG-группу. На root-only временной копии полная проверка прошла после замены только этого маршрута; snapshot не менялся. Перед записью создана root-only резервная копия `/opt/etc/hestia`, opkg status и предыдущего рабочего IPK в `/opt/tmp/hestia-profile-repair-20261109-1249/`. Старый пакет сверили с SHA-256 из предыдущего свидетельства.

**Установка и восстановление.** После профильной правки локальная и удалённая SHA-256 нового IPK совпали. Первая команда `opkg install` обновила пакетные файлы, но postinst завершился ошибкой `managed service operation failed: smoke`; автоматического rollback нет. Файлы профиля остались валидны, default route не изменился. Штатный `/opt/etc/init.d/S99hestia start` затем прошёл, подтвердив базовую готовность supervisor. После этого документированная команда `/opt/bin/opkg configure hestia` завершилась с кодом 0.

**Фактический результат.** Итоговый `opkg status hestia`: версия `20261109-130906-db76edb7f3e1`, `Status: install user installed`, `Architecture: aarch64-3.10`. Readiness supervisor прошла, marker готовности является обычным файлом, package-maintenance marker отсутствует. Managed profile, controller snapshot и sing-box config валидны. GET `/`, `/api/groups-and-rules`, `/api/physical-connections` и `/api/awg-underlays` вернули HTTP 200. IPv4 default route до и после имеет SHA-256 `f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`; IPv6 default route отсутствует до и после. В ingress table `32732` наблюдаются маршрут `default dev opkgtun0`, protocol `253`, metric `1000`, и unreachable fallback, protocol `253`, metric `32767`.

Во время прогона владелец отключил `hestia-client` от policy. Сам Hestia policy не менял; read-only RCI показывает, что `Policy2` всё ещё разрешает `OpkgTun0`. После postinst-конфликта opkg оставил новые package defaults как root-only файлы `*-opkg`; их сохранили для ручного рассмотрения.

**Границы вывода.** Проверены установка пакета, supervisor, конфигурации, GET API, активная Hestia ingress table и неизменность IPv4/IPv6 default-route snapshot. Клиентский TCP/UDP dataplane, обратный путь, VPN egress, DNS, IPv6 forwarding, reboot recovery и fail-closed при смене policy не проверялись. `hestia-client` остался отключён от policy, пользовательский трафик не генерировался. В supervisor log сохранилось предупреждение о ingress reconciliation из предыдущего неуспешного postinst; при итоговой проверке supervisor был готов и обе route entries присутствовали.

**Воспроизведение.** Повторить локально `GOCACHE=/private/tmp/hestia-go-cache-task make build`, проверить bundle через `scripts/shared/common.py:verify_bundle`, затем сверить IPK SHA-256. Перед целевым обновлением подтвердить профиль, snapshot, резервную копию, политику, версию и архитектуру. Загрузить IPK в inbox через HTTP endpoint `hestia-cli`, сверить удалённый SHA-256 SSH-командой и запустить `opkg` через SSH alias. SSH используется только для удалённых команд, не для передачи содержимого файлов. Если postinst завершится ошибкой, не повторять установку автоматически: собрать профильную и lifecycle диагностику; `opkg configure hestia` выполнять только после подтверждения валидности профиля и восстановления причины отказа.

## Установка исправленного trace IPK на KN-1012 — 9 ноября 2026 года

После независимого code/security review исправленный пакет `20261109-155544-db76edb7f3e1` был установлен на KN-1012. IPK SHA-256 совпал локально и на роутере; `opkg` показал `install user installed`, supervisor readiness прошла, package-maintenance marker отсутствовал. Read-only GET `/`, `/api/groups-and-rules`, `/api/physical-connections` и `/api/traffic` ответили HTTP 200. IPv4 default-route hash совпал до и после обновления, IPv6 default route был пустым до и после. Конфигурация оператора осталась на месте; отличавшиеся от package defaults conffiles получили суффикс `-opkg`.

На установленном пакете проведён синхронный 15-секундный trace с тестовым tuple. `/api/traffic` подтвердил сохранение сводки. В трассе два SYN наблюдались на `br0`, но ни один не появился на `opkgtun0` или в sing-box inbound. Это подтверждает работу наблюдателя и локализует следующий этап между bridge и OpkgTun, не определяя фактическую причину отсутствия перехода. [Протокол установки и границы](evidence/install-20261109-155544/check.txt); [пакетная трасса и tcpdump клиента](../keenetic-client-dataplane/evidence/trace-installed-20261109-155544.txt).

## Readiness и candidate backend timeout на KN-1012 — 11 ноября 2026 года

Первый повторный пакет `20261111-160750-77d6f73ccf3d` с 47-минутным ожиданием supervisor дошёл до готовности и запуска OpkgTun migration. Migration завершилась на `candidate-backend-check`: процесс sing-box проверки превысил внутренний предел `2m1.532s`; внешний предел команды составлял пять минут. `opkg` оставил `install user unpacked` и maintenance marker. Главные IPv4/IPv6 route snapshots совпали с backup. IPv4/IPv6 rule tables после supervisor guard reconciliation содержали дополнительные Hestia guard rules; они сохранены и не удалялись вручную. В коде следующий кандидатный timeout повышен до 10 минут, а общий предел migration — до 15 минут. Новая установка нужна для проверки этой поправки. [Evidence и ограничения](evidence/update-20261111-160750-attempt.txt).

## Activation smoke timeout на KN-1012 — 11 ноября 2026 года

Пакет `20261111-162047-77d6f73ccf3d` прошёл preflight, поднял supervisor, восстановил AWG runtime и завершил candidate backend validation после более чем двух минут работы. Миграция дошла до активации и вернула `activation: managed service operation failed: smoke`; rollback восстановил исходную конфигурацию и остановил службы с guard-состоянием. Main IPv4/IPv6 route hashes остались совпадающими с backup. Supervisor log показывает, что во время этого запуска не удалось стабильно установить TUN route; текущая причина smoke не сохраняется деталями через IPC. Проверка истории показала, что commit `880c07c` добавил пятсекундное окно selector convergence. Оно повышено до 30 секунд как вероятное исправление, с регрессионной проверкой. Следующий target install должен подтвердить или опровергнуть гипотезу. [Свидетельство прогона](evidence/update-20261111-162047-attempt.txt).

## Установка IPK `20261111-163505` на KN-1012 — 11 ноября 2026 года

После увеличения selector convergence timeout до 30 секунд IPK `20261111-163505-77d6f73ccf3d` установлен успешно: `opkg` завершился с кодом 0, статус — `install user installed`, supervisor readiness подтверждена, package-maintenance marker снят. Read-only `GET /` и `/api/groups-and-rules` ответили HTTP 200. `/api/physical-connections` не ответил за 30 секунд. После запуска сервисов память была ограничена (около 20 MiB доступно, swap отсутствует); отдельные managed-profile/backend проверки остановлены, readiness probe повторно прошёл после остановки этих проверок. IPv4 default route остался через тот же gateway; IPv6 default route отсутствует как и в backup. Aggregate route hashes изменились при успешной OpkgTun migration; ручной cleanup не выполнялся. Клиентский трафик, VPN egress, policy behavior и rollback не проверялись. [Полное свидетельство, hash пакета и ограничения](evidence/update-20261111-163505-installed.txt).

## Исправление первого сохранения проверок качества и установка на KN-1012 — 11 ноября 2026 года

**Вопрос и критерии.** Исправить HTTP 503 при первом сохранении проверок качества и обновить рабочий KN-1012, подтвердив установленный пакет, готовность supervisor, наличие каталога настроек качества, сохранность default routes и фактическую работу добавленных проверок.

**Изменение и сборка.** Причина была в отсутствующем `/opt/var/lib/hestia/quality`: GET отдавал defaults, но сохранение не могло создать временный файл в несуществующем каталоге. `postinst` теперь создаёт этот каталог с режимом `0700` до запуска службы. Регрессионный тест сначала воспроизвёл отсутствие каталога, затем прошли все 17 тестов `scripts/build`, `make fmt-check`, `make docs-check`, `sh -n deploy/keenetic/ipk/postinst` и `git diff --check`. Code review не выявил замечаний; ShellCheck отсутствовал в среде. Сборка `20261111-175949-745d70b83179`, IPK SHA-256 `83fd92a2f6a952abd7f9fcfb05f0bff794a9617f654af450256e5063bbc6e1ee`.

**Установка и результат.** Перед обновлением Hestia была штатно остановлена по инструкции владельца: доступная память выросла примерно с 23 MiB до 179 MiB. После этого `opkg install` завершился успешно; пакет имеет статус `install user installed`, supervisor готов, maintenance marker снят, каталог `/opt/var/lib/hestia/quality` существует с режимом `0700`. Отличавшиеся от package defaults conffiles сохранены `opkg` отдельно, существующая конфигурация не перезаписывалась. IPv4 default route hash до и после — `f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`; IPv6 default route отсутствовал до и после.

В панели сохранены шесть проверок: UDP, TCP, ICMP, DNS, HTTPS и HTTP/3; для новых ICMP/DNS/HTTPS/HTTP/3 заданы интервал 30 секунд и тайм-аут 3 секунды. На активном выходе панель показала ICMP 45/45, DNS 44/44, HTTPS 16/16 и HTTP/3 9/10 успешных измерений на момент фиксации. На двух недоступных в тот момент выходах HTTPS/HTTP/3 не проходили или поддерживались частично; один выход сообщил, что ICMP не поддерживается. После запуска Hestia свободная память была около 19 MiB (available около 26 MiB в последнем снимке), supervisor оставался готов.

Подробный протокол, хеши, результат UI и ограничения: [свидетельство исправления и установки](evidence/update-20261111-quality-settings.txt).

## Лимиты памяти sing-box на KN-1012 — 11 ноября 2026 года

**Запрос и изменение.** Владелец попросил запустить Hestia с `GOMEMLIMIT=90MiB` и `GOGC=50` только для sing-box и остановить службы, если занято более 85% памяти роутера. Supervisor задаёт дочерним процессам явный список окружения, поэтому экспорт переменных в init-оболочке не сработал бы. В `managedServiceEnvironment` добавлены обе переменные для роли Router; прочие службы их не получают. Регрессионный тест это проверяет.

**Проверки и пакет.** `go test -count=1 ./internal/services/entware` прошёл, `make build` собрал bundle `20261111-222317-d87148df7d8a`, IPK SHA-256 `96583100e80a3cdeede57f9787c60bd618be3d9ed6a65f216aa379bef9ad3bac`. `make fmt` завершился, `make docs-check` и `git diff --check` прошли. `make check` остановился на отсутствующем в среде `shellcheck`; `go vet` из этой команды прошёл до этого шага.

**Установка и фактический запуск.** Перед установкой Hestia была остановлена, установленная версия `20261111-175949-745d70b83179`, `service-check-idle` подтвердил отсутствие managed процессов. Подготовлен root-only backup конфигурации и статуса opkg; прежний IPK скопирован туда, его SHA-256 совпал с локальным `83fd92a2f6a952abd7f9fcfb05f0bff794a9617f654af450256e5063bbc6e1ee`. Новый IPK передан через LAN-bound `hestia-cli`; HTTP upload вернул 201, удалённый hash совпал с локальным. `opkg install` завершился успешно; статус `install user installed`, supervisor готов. Изменённые conffiles сохранены opkg как `*-opkg`, существующий профиль оставлен без замены.

Read-only проверка `/proc/<pid>/environ` фактического процесса sing-box подтвердила `GOMEMLIMIT=90MiB` и `GOGC=50`. Пятиминутный наблюдатель сравнивал колонку `used` команды `free` с её `total` и при 85% должен был вызвать `/opt/etc/init.d/S99hestia stop`. Срабатывания не было: показатель колебался примерно от 63% до 64%, supervisor остался готов. Владелец в ходе проверки сообщил отдельный показатель 207/512 MiB (около 40%); это отличается от снимка BusyBox `free`, поэтому оба показателя не следует считать одним и тем же измерением. IPv4 default-route hash до и после — `f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`; IPv6 default route отсутствовал до и после.

Полная последовательность, хеши и наблюдения за памятью: [свидетельство runtime лимитов](evidence/runtime-gomemlimits-20261111.txt). Пятиминутное окно не подтверждает поведение после длительной нагрузки или перезагрузки.

## Настройки GC 140 MiB / 100 на KN-1012 — 12 ноября 2026 года

По предложению владельца в сборке `0.1.8` для процесса sing-box установлены `GOMEMLIMIT=140MiB` и `GOGC=100`; supervisor и остальные службы сохраняют прежнее окружение. Изменение покрывает regression test. `make fmt`, `go test -count=1 ./internal/services/entware` и `make build` прошли. `verify_bundle` подтвердил Keenetic bundle `0.1.8`; IPK `dist/artifacts/0.1.8/keenetic-arm64-experimental/hestia_0.1.8_aarch64-3.10.ipk`, SHA-256 `d81f9a228a3853848b02dbc930cacbce2eeadc1a6c642fe4a58286117dd35e6a`.

Владелец установил пакет и перезагрузил KN-1012. Read-only проверка после перезагрузки подтвердила `Version: 0.1.8`, `Status: install user installed`, readiness supervisor и фактические `GOGC=100`, `GOMEMLIMIT=140MiB` в окружении sing-box. IPv4 default-route hash сохранился (`f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`).

По сообщению владельца, Ookla Speedtest.net по-прежнему показывает около 30 Мбит/с, а CPU роутера загружен на 80–90%. Это не контролируемый повторный замер с сохранённым результатом Speedtest и без сведений о сервере/направлении, но прироста, заметного владельцу, после настройки GC нет. Поэтому изменение GC не устранило наблюдаемое ограничение; оно не доказывает и не исключает конкретную причину на dataplane. Следующий диагностический прогон должен снимать загрузку по ядрам, процессы и softirq во время одного и того же многопоточного Ookla теста, а для оценки GC нужны runtime-метрики sing-box. [Свидетельство установки и результата](../keenetic-client-dataplane/evidence/throughput-gc-20261112.txt).

## Начальный preflight маршрутизации `0.1.11` — 13 ноября 2026 года

По поручению владельца собран пакет Keenetic `0.1.11` с изменённым порядком
маршрутов ingress. До `opkg` новый компилятор запущен только над временной
копией текущего managed-профиля. Он отказал с `unsafe Keenetic ingress route
group: default`. Безопасный список групп содержит только «Остальной мир»;
группа «Россия» включает прямой `keenetic-uplink` на `eth3`, Msk AWG 3.1 и
Msk H2, а включённая country map назначает RU в `default`. Новый guard запрещает
прямой WAN как один из выходов ingress-группы. Это тот же кандидатный
compile, который выполняет `postinst` через `hestia -enable-keenetic-ingress`.

IPK `hestia_0.1.11_aarch64-3.10.ipk` собран из текущего рабочего дерева
(SHA-256 `2e7a43314507469063befab22972adf13e3ed095079ff051b5118ceae991ce66`);
предыдущий `0.1.10` сохранён локально и передан на роутер для возможного
восстановления. Хеши обоих пакетов совпали после загрузки. Установка и остановка
Hestia не выполнялись: preflight показал, что `postinst` отклонит текущий
профиль и оставит службы остановленными. Установленный `0.1.10` остался
`install user installed`, supervisor готов, IPv4 default-route hash сохранился
как `f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`;
IPv6 default route отсутствует. Временная проверочная staging-копия удалена.

Временный LAN-only `hestia-cli` listener остановлен. Обнаруженный до этого
listener на `198.51.100.11:8081` не запускался и не изменялся. Проверка не
подтверждает маршрутизацию клиентских пакетов и не включает `opkg install`.
После этого Product Owner уточнил, что прямой выход к провайдеру должен
оставаться допустимым вместе с VPN; критерий безопасности изменён на точный
`keenetic-uplink`, привязанный к проверенному default-route устройству. Повтор
с новым критерием зафиксирован ниже. Полный вывод начального preflight без
профиля и секретов записан в
[свидетельстве preflight](evidence/update-0.1.11-preflight-20261113.txt).

## Установка маршрутизации ingress на KN-1012 — 13 ноября 2026 года

После уточнения владельца новый guard разрешает провайдерский выход только как
`keenetic-uplink`, привязанный к фактически выбранному default-route устройству.
Также добавлена совместимость с точным старым порядком ingress fallback до
domain/GeoIP правил: `managed_profile` нормализует только полностью совпадающий
предыдущий route generation; дополнительные расхождения сохраняют отказ.

IPK `0.1.13` прошёл staged compiler, managed validation и `sing-box check` на
текущем профиле. Создан root-only backup с конфигурацией и подтверждённой копией
rollback IPK `0.1.10`. После `opkg install` пакет имеет `install user installed`,
supervisor готов, maintenance marker отсутствует. Managed profile и sing-box
config валидны; panel `/`, `/api/groups-and-rules` и
`/api/physical-connections` отвечают HTTP 200. IPv4 default-route hash не
изменился; IPv6 default route отсутствует.

IP-literal проба из `hestia-client` к `77.88.8.8` получила HTTP 404. Журнал
сообщил `RU`, `geoip-RU`, группу «Россия» и выбранное подключение
`keenetic-uplink`; запись осталась `unconfirmed`, поэтому независимого
подтверждения физического egress нет. Контрольный запрос к `1.1.1.1` (AU)
вернул HTTP 301, но журнал показал только `opt-in flow trace summary` без
группы и подключения, поэтому выбор Msk AWG 3.1 или Msk H2 не подтверждён.
Полные команды, хеши и границы вывода приведены в
[свидетельстве установки](evidence/update-0.1.13-installed-20261113.txt).

## Журнал выбранного выхода в трафике — установка `0.1.14`, 13 ноября 2026 года

**Вопрос и критерии.** Собрать и установить журнал исхода маршрутизации: выбранное
подключение показывается по его имени; провайдерский интерфейс отображается как
«ПАКТ»; явная блокировка — «Заблокировано»; отсутствие зафиксированного выхода —
«Не определено». Фильтр `output=unknown` должен быть доступен через API.

**Сборка.** `make build` собрала bundle `0.1.14` из ревизии
`03e710d41c31991bac3fad0d0d92cf86e82829a8`, рабочее дерево содержало изменения.
`verify_bundle` подтвердил манифест Keenetic ARM64. IPK
`hestia_0.1.14_aarch64-3.10.ipk`, SHA-256
`34b931569debec80c11e2ce4add89c0c9dcd6210e221b7655ab1c142f88a95f7`.

**Установка и проверки.** На Keenetic Giga KN-1012 с KeeneticOS
`5.02.B.3.0-2`, Entware `aarch64-3.10`, установлен `0.1.14` поверх `0.1.13`.
Перед `opkg install` в root-only каталог сохранены конфигурация и статусы,
default routes, а также rollback IPK `0.1.13` с проверенным SHA-256
`078493f703a8dcea5dc0c0d26e1878a8020035dc6f6a46c6460abf2b21da43ab`.
После установки статус пакета — `install user installed`, supervisor готов,
maintenance marker отсутствует. Managed profile, controller snapshot и
sing-box config проходят проверки. Хеши `profile.json`, `snapshot.json` и
`sing-box.json` остались соответственно
`b933203a0f64b2cab8b546ca486bde8a600224c3a640a8bbbd557763453c65e7`,
`f6c8bb25132558bb8f4b33ae19e9af5333292573f8d40e638ed9614b6ee6ae20` и
`a3680e9ba838d6517b502fd574377f74be8cdb5adb81b518425a33d8697b719e`.
IPv4 default-route hash до и после —
`f06c293b969676f64f57820103587f105084b9f90ca6c30640a925da0eba3871`;
IPv6 default route отсутствует до и после.

С `hestia-client` панель и API групп/правил, физических подключений и журнала
ответили HTTP 200; запрос `/api/traffic?output=unknown&limit=1` также вернул
HTTP 200. UI-подписи и фильтр проверены локальными тестами до сборки; на роутере
новый пользовательский поток специально не создавался, поэтому этот прогон не
подтверждает фактический физический egress конкретного адреса. Временный
LAN-bound `hestia-cli` listener и загруженные IPK удалены; прежний listener на
`198.51.100.11:8081` не затронут. Полные хеши и результат проверок приведены в
[свидетельстве установки](evidence/update-0.1.14-traffic-journal-20261113.txt).

## Установка групповых проверок и управления подключениями — `0.1.15`, 13 ноября 2026 года

По поручению владельца собран и установлен Keenetic IPK `0.1.15` со всеми изменениями этого чата: журналом с QUIC и обновлением, групповыми проверками качества, переключателями VPN, скрытым служебным входом и автоматическим опросом состояний. SHA-256 пакета — `36a2cb8cded0c8c636ae2a3f4f38d99d2468b85d27f9746b19c35ea193b71545`; комплект прошёл `verify_bundle`.

До установки проверены аппаратный preflight нового IPK, компиляция текущего managed-профиля во временный каталог, snapshot и sing-box config. В root-only `/opt/tmp/hestia-deploy-0.1.15-20261113-ui` сохранены конфигурация, настройки проверок и политик, статус opkg, default routes и rollback IPK `0.1.14`. Передача выполнена через авторизованный LAN hestia-cli, все контрольные суммы совпали.

`opkg` завершился успешно: `Version: 0.1.15`, `Status: install user installed`. Supervisor готов, maintenance marker отсутствует. Рабочие profile/snapshot/sing-box JSON сохранили исходные хеши; default IPv4/IPv6 routes не изменились. Установленные бинарники и index.html совпали с артефактом. Панель и API отвечают HTTP 200. Chromium на установленной панели подтвердил версию `0.1.15-keenetic`, групповой диалог проверок, пять переключателей VPN, скрытый вход, отсутствие ручных кнопок обновления подключений/качества, автоматические запросы и изменения журнала.

Рабочие VPN для проверки не отключались; фактический packet-level fail-closed и распознавание QUIC на устройстве этим прогоном не измерялись. Два окна оценки остались 60 минут, наборы сохранили шесть типов; при сверке TCP-цели одной группы отличались от backup, это текущее значение не перезаписывалось. Smoke-скрипты не выполняли операций записи; происхождение изменения TCP-целей не установлено. Полная последовательность и границы вывода — в [свидетельстве установки](evidence/update-0.1.15-ui-20261113.txt).

## Исправление переключателей и обновления журнала — `0.1.16`, 13 ноября 2026 года

Установлен общий IPK `0.1.16` с исправлением конфликта фоновых чтений и переключения VPN, независимым административным включением и подтверждением завершения операции. По поручению владельца включены готовые изменения журнала из другого чата: ToggleSwitch с включённым автообновлением и сохранением строк до нового ответа.

SHA-256 IPK — `31b1b9fd2293ef523bdbba7373c07d9e36e3b870bdd71b3b041cda38d619d827`. Манифест и переданные файлы проверены; аппаратный preflight и staged compiler/snapshot/sing-box check прошли до `opkg`. Сохранены свежие настройки и проверенный rollback `0.1.15`. Установка завершилась успешно, supervisor готов. JSON-данные профиля и default routes сохранились; изменился только формат сериализации profile.json. Live-проверка Laurel выполнила выключение и включение в одной вкладке без ошибок, восстановила исходные флаги и проверила обе API-квитанции. Подробности — в [отчёте проверки](../physical-connections/README.md#исправление-переключения-laurel--установка-0116-13-ноября-2026-года) и [свидетельстве](../physical-connections/evidence/vpn-toggle-fix-20261113.txt).
