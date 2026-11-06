# Документация Гестии

[Главная страница проекта](../README.md)

- [Проверки и инструменты стенда](../tests/lab/README.md)
- [Отчёты и свидетельства испытаний](../experiments/README.md)

При добавлении документа в этот каталог или его подкаталоги включайте ссылку в соответствующий раздел оглавления.

## Требования, архитектура и исследования

- [Требования к Гестии](requirements.md)
- [Дорожная карта](roadmap.md)
- [Предлагаемая архитектура](architecture.md)
- [Устройство Keenetic и интеграция Hestia](keenetic-platform.md)
- [Дорожная карта модульной архитектуры и поставки Keenetic](keenetic-roadmap.md)
- [Рекомендуемые устройства](hardware.md)
- [Исследование готовых решений](research.md)
- [Готовые компоненты для контроллера](go-components.md)
- [Предложения по изменению API](api-proposals.md)

## Маршрутизация, DNS и качество связи

- [Первый MVP контроллера](mvp-routing.md)
- [Независимые измерения каналов](observer.md)
- [Выбор основного выхода по нескольким целям](group-quality.md)
- [Автоматическое переключение UDP до одного адреса](scoped-steering.md)
- [Сохранение порядка групп и выходов](group-order.md)
- [Применение привязки доменного списка](list-binding.md)
- [Настройки DNS и управление прогревом](dns-settings.md)
- [Смена реального IPv4 при сохранённом FakeIP](dns-rotation.md)

## Панель управления

- [Первый экран локальной панели](frontend.md)
- [Страницы и дорожная карта панели](frontend-roadmap.md)
- [Каталог компонентов фронтенда](frontend-ui-kit-catalog.md)
- [Дизайн Keenetic как ориентир](keenetic-design.md)

## Спецификации функций

- [Диагностическая сборка Keenetic](features/keenetic-diagnostics.md)
- [Платформенный модуль управления службами](features/platform-services.md)
- [Модули системных операций, хранения и сети](features/platform-modules.md)
- [Настройки пользователя](features/admin-password.md)
- [Создание групп подключений](features/connection-groups.md)
- [Качество связи подключений](features/connection-quality.md)
- [Редактор доменных списков](features/domain-lists-editor.md)
- [Физические и виртуальные подключения](features/physical-connections.md)
- [Подключение Hysteria 2](features/hysteria2.md)
- [WireGuard / AmneziaWG userspace-коннектор](features/amneziawg-connector.md)
- [Несколько одновременных подключений WireGuard и AmneziaWG](features/multiple-wireguard.md)
- [Редактор подключения WireGuard](features/wireguard-editor.md)
- [Через какое подключение устанавливается WireGuard](features/wireguard-underlay.md)
- [Журнал трафика](features/traffic-journal.md)
- [Редизайн панели по образцу Keenetic](features/panel-redesign.md)

## Испытания и эксплуатация

- [Разворачивание Hysteria на внешнем сервере](../deploy/docs/hysteria2-server.md)
- [Правила работы с виртуальными машинами](virtual-machines.md)
- [План испытаний и открытые вопросы](validation.md)
- [План первого нагрузочного испытания на ВМ](load-test-vm.md)
- [Мониторинг на Гестии](monitoring.md)

## Правила разработки и роли

- [Bash для сценариев развёртывания](bash-style-guide.md)
- [Инженер по сетям Linux](agent-prompts/linux-network-engineer.md)
- [Инженер по встраиваемому Linux](agent-prompts/embedded-linux-engineer.md)
