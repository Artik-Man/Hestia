# Read-only RCI and Linux netdev correlation

Observed on 2026-11-07 at about 18:19 UTC on Keenetic Giga KN-1012, KeeneticOS 5.2 Beta 3. Two authenticated HTTP GET operations returned HTTP 200 through the existing SSH forward to router loopback port 79:

- `GET /rci/show/interface` returned the logical connection `GigabitEthernet1`, description `ПАКТ`, interface name `ISP`, connected/up, and `defaultgw=true`; child `GigabitEthernet1/0` was up and typed `Port`.
- `GET /rci/show/ip/route` returned the default destination `0.0.0.0/0` through `GigabitEthernet1`.

On the Linux side, the default route in `main` and policy-routing tables `4096`, `16385`, `4103`, and `4105` used `eth3`. The LAN bridge `br0` contained `eth2.1`. The allowlisted results are in [result-sanitized.json](result-sanitized.json) and [kernel-summary.txt](kernel-summary.txt); raw RCI JSON, gateway addresses, and interface addresses were not saved.

This correlates `eth3` with the active default Internet path belonging to ПАКТ and identifies `eth2` as LAN-side. The RCI response itself does not include the Linux kernel names `eth2` or `eth3`; the correlation combines RCI's logical default route with the Linux route tables. It does not establish a direct hardware/netdev mapping from `GigabitEthernet1/0` to `eth3`.

To reproduce, open the already authorized SSH local forward to `127.0.0.1:79`, then build the shared-client probe from [source.go](source.go) inside `backend/` and run it with the owner-only token file. It makes only the two GET requests above and emits allowlisted fields. For the Linux side, inspect only default routes using `ip route show table all` filtered to destination `default`, retaining table, `dev`, and metric; separately check whether `/sys/class/net/br0/brif/eth2.1` exists. No configuration was changed.
