# Сценарии проекта

Операции независимы: сборка не подключается к стенду, установка не пересобирает исходники, тест установленной версии не обновляет приложение.

| Операция | Команда | Инструкция |
|---|---|---|
| Сборка Linux и экспериментального Keenetic | `make build` | [build](build/readme.md) |
| Диагностический комплект Keenetic без подключения к роутеру | `python3 scripts/build-keenetic-diagnostics/run.py` | [build-keenetic-diagnostics](build-keenetic-diagnostics/readme.md) |
| Проверка исходников без стенда | `make test-source` | [test-source](test-source/readme.md) |
| Установка/обновление готового Linux-комплекта | `make deploy-dev BUNDLE=/path/linux-arm64` | [deploy](deploy/readme.md) |
| Ручная экспериментальная поставка IPK на Keenetic | по процедуре | [keenetic-ipk](deploy/keenetic-ipk.md) |
| Проверка установленного dev | `make test-dev` | [test](test/readme.md) |
| Общие описания стендов, манифесты и отчёты | — | [shared](shared/readme.md) |

`deploy-prod` и `test-prod` явно выбирают prod. Для другого стенда используются `make deploy STAND=... BUNDLE=... TYPE=linux` и `make test-installed STAND=...`. Агентам по-прежнему требуется отдельное поручение владельца на prod или Keenetic. Питанием машин эти команды не управляют.

Контракты и критерии — в [спецификации](../docs/validation.md#согласованное-разделение-сценариев). Прежний смешанный `tools/validate.sh` заменён этими четырьмя операциями.

## Состав сценариев

| Файлы | Назначение |
|---|---|
| [build/run.sh](build/run.sh), [build/run.py](build/run.py) | Точка входа и сборка двух комплектов с манифестами. |
| [test-source/run.py](test-source/run.py) | Проверки исходников без подключения к стенду. |
| [deploy/run.sh](deploy/run.sh), [deploy/run.py](deploy/run.py) | Проверка выбранного комплекта, подключение и доставка на стенд. |
| [deploy/apply.sh](deploy/apply.sh) | Обновление установленного приложения и выбор первичной установки. |
| [deploy/fresh.sh](deploy/fresh.sh) | Первая установка Linux; напрямую обычно не запускается. |
| [test/run.py](test/run.py) | Оркестрация проверок установленной версии и сбор отчёта. |
| [test/guest.sh](test/guest.sh) | Фазы подготовки, проверки и контроля сохранности на стенде. |
| [test/network.sh](test/network.sh) | Изолированные сетевые сценарии. |
| [test/read_only.py](test/read_only.py) | Чтение локального API без изменения настроек. |
| [shared/common.py](shared/common.py) | Транспорт, идентичность стенда, проверка манифестов и отчёты. |
| [shared/paths.sh](shared/paths.sh) | Проверка путей перед привилегированными операциями. |

Файлы `test_*.py` рядом со сценариями проверяют их отказы и защитные условия; они включены в `make test-workflows` и `make check`. Параметры и зависимости перечислены в `readme.md` соответствующего каталога по ссылкам выше.
