# Отчёты и свидетельства испытаний

Здесь хранятся вопросы опытов, условия прогонов, результаты и исходные свидетельства в `evidence/`. Дата и версия в каждом отчёте определяют границы вывода: успешный исторический опыт не означает, что текущее приложение или любое устройство прошло ту же проверку.

Исполняемые сценарии, тесты и конфигурации находятся в [tests/lab](../tests/lab/README.md). Структура имён сохранена: отчёту `experiments/dns-restart/README.md` соответствует код `tests/lab/dns-restart/`. Общие модули соседних сценариев нужны для повторного анализа захватов и регрессионных тестов; копируйте дерево стенда с сохранением структуры.

## Что где хранить

Исследовательские MVP для проверки возможностей Keenetic хранятся в `experiments/<исследование>/prototype/`, рядом с отчётом и `evidence/`. Это отдельные программы для проверки гипотез на устройстве; они не входят в набор тестов Гестии. Такое размещение согласовано владельцем для исследовательских прототипов Keenetic.

- [Управление виртуальными подключениями Keenetic](keenetic-virtual-management-20261106/README.md) — сверка runtime и проверка управления существующими VPN.
- [Управление Ethernet-портами Keenetic](keenetic-ethernet-management-20261106/README.md) — аудит и подготовка ограниченного аппаратного опыта.
- [Управление Wi-Fi/WISP Keenetic](keenetic-wifi-management-20261106/README.md) — аудит и подготовка опыта с сохранённым профилем телефона.

- [Локальный VLESS на Keenetic](keenetic-vless-local/README.md).
- [Локальный Hysteria 2 с TLS](keenetic-hysteria2-local/README.md).
- [FakeIP и локальные потоки на Keenetic](keenetic-fakeip-local/README.md).
- [FakeIP и смена адреса после TTL на Keenetic](keenetic-fakeip-ttl/README.md).
- [Переключение локальных выходов и блокировка на Keenetic](keenetic-exit-failover/README.md).
- [DNS CNAME и TCP fallback на Keenetic](keenetic-dns-fallback/README.md).
- [UDP и блокировка sing-box на Keenetic](keenetic-singbox-udp-block/README.md).
- [Демон AmneziaWG и приватный UAPI](keenetic-awg-uapi/README.md).
- [Локальный DNS sing-box по UDP/TCP](keenetic-dns-local/README.md).
- [Совместимость awg-tools на Keenetic](keenetic-awg-runtime/README.md).
- [Создание и очистка TUN на Keenetic](keenetic-tun/README.md).
- [TUN-вход Hestia через OpkgTun на Keenetic](keenetic-client-dataplane/README.md) — A/B sing-box stack на KN-1012 подтвердил восстановление клиентского TCP при `gvisor`; исправление установлено Hestia `0.1.7`, default route сохранился. PPE/FASTNAT и длительная нагрузка отдельно не проверялись.
- [Проверка возможностей RCI/CLI только для чтения на KN-1012](keenetic-rci-readonly/README.md) — выборочная проверка команд `show`.
- [Незавершённая инвентаризация Netfilter](keenetic-netfilter-readonly/README.md).
- [Незавершённая проверка атомарного хранения](keenetic-storage-atomic/README.md).
- [Незавершённое исследование Entware rc.func](keenetic-entware-rcfunc-readonly/README.md).
- [IPv6 SOCKS TCP/UDP и блокировка sing-box на Keenetic](keenetic-ipv6-loopback/README.md).

- [Подготовка диагностики Keenetic](keenetic-capabilities/README.md) — локальная сборка и матрица ещё не выполненных аппаратных проверок.
- [Локальная сборка Keenetic IPK](keenetic-ipk-packaging/README.md) — сборка и структурная проверка Entware IPK; установка и opkg lifecycle на KN-1012 не проверялись.
- `tests/lab/` — поддерживаемые инструменты проверки, тестовые прототипы и их fixtures. Команда `make test-lab` запускает только модульные тесты, без доступа к ВМ.
- `experiments/<опыт>/README.md` — отчёт конкретного опыта: вопрос, среда и версия кода, ожидание и результат, ограничения и воспроизведение.
- `experiments/<опыт>/evidence/` — неизменённые исходные журналы, конфигурации прогонов и захваты. Исторические пути и имена ВМ внутри них сохраняются.
- `docs/` — действующие требования, архитектура и выводы со ссылками на отчёты.

Перед новым сетевым прогоном выберите стенд по [правилам ВМ](../agents/virtual-machines.md). Старые имена ВМ в отчётах описывают прошлую среду; они не разрешают создание ВМ, доступ к prod или управление питанием dev. В каталоге есть и незавершённые отчёты: статус определяется текстом конкретного отчёта.

## Историческая подготовка ВМ

6 ноября 2026 года из рабочего дерева удалены `experiments/fakeip/vm/lima.yaml` и `experiments/fakeip/vm/provision.sh`. Это прежний способ создания отдельного Debian ARM64-стенда и установки sing-box, а не действующая инструкция управления ВМ. Его исходники сохранены в Git в ревизии `66bb2faafc3c053e3010936a3a9d1fa89e70337b`.

Для изучения или точного восстановления старого комплекта извлеките его в отдельный локальный каталог из корня репозитория:

```sh
archive_dir=$(mktemp -d)
git archive 66bb2faafc3c053e3010936a3a9d1fa89e70337b experiments/fakeip | tar -x -C "$archive_dir"
```

Эта команда только извлекает файлы. Исторические команды подготовки из отчёта FakeIP относятся к извлечённому комплекту. Их запуск и создание либо пересоздание ВМ требуют разрешений по действующим правилам. Для текущего dev используется [сценарий установки](../tests/lab/dev-validation/install.sh), описанный в [отчёте dev](dev-validation/README.md); он не заменяет воспроизведение старого опыта на чистом образе.

При очистке отчёты и существующие свидетельства сохранены на прежних путях. Пять модульных тестовых наборов и общие зависимости перенесены без сокращения покрытия. Сетевые сценарии во время этой перестройки не запускались.
