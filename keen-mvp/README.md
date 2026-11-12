# Keen-MVP: видимый OpkgTun для Keenetic

`keen-mvp` — отдельный экспериментальный Entware-пакет для первого этапа клиентского dataplane Hestia. Он создаёт NDM-интерфейс `OpkgTun0` и оставляет его доступным для подключения к Linux TUN `opkgtun0` из sing-box в Hestia.

Пакет устанавливается отдельно от Hestia:

```sh
python3 keen-mvp/build.py
opkg install keen-mvp/dist/keen-mvp_0.1.0-3_aarch64-3.10.ipk
```

При `postinst` пакет запускает `/opt/etc/init.d/S52keen-mvp`. Программа работает от root, использует фиксированное имя `OpkgTun0`, адрес NDM `172.31.250.1/32`, MTU 1500 и `ip global auto`, чтобы Keenetic публиковал состояние интерфейса в WebUI. Она отказывается менять уже существующий интерфейс, если не находит собственный root-only marker. При штатной остановке закрывает TUN и удаляет только принадлежащий пакету NDM-объект. Если процесс был аварийно завершён, повторный `start` восстановит объект по marker; `stop` также удаляет оставшийся объект после проверки владения.

Прототип не открывает `/dev/net/tun`: единственным владельцем TUN file descriptor должен быть sing-box. Он не задаёт `defaultgw`, системный default route, policy rules или маршруты; не вызывает `system configuration save`; не читает и не пересылает пакеты и не запускает VPN-выход. `stop` удаляет собственный NDM-объект и marker; при запущенном Hestia сначала нужно остановить Hestia, чтобы NDM interface не был удалён у активного sing-box. На KN-1012 установлен пакет `0.1.0-2`; он удерживает TUN FD и требует обновления до `0.1.0-3` для handoff. Обновление штатно остановит старую службу и на короткое время пересоздаст NDM-объект. После обновления поле `global` должно оставаться `yes`, `defaultgw` — `no`. Product Owner подтвердил WebUI карточку `Keen-MVP` с типом `OpkgTun` и подписью «Резервное соединение» ([отчёт](../experiments/keenetic-client-dataplane/README.md)).

Локальную сборку можно выполнить командой `python3 keen-mvp/build.py`; IPK `0.1.0-3` переводит пакет в режим NDM keeper без открытия TUN FD. На KN-1012 пока установлен `0.1.0-2`; переход и policy selection не проверялись.
