import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

/** Exercises bounded virtual scrolling, snapshot refresh, combined filters and saved settings through the built panel. */
test("traffic journal reaches rows past 500 and refresh preserves its filters", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    await page.emulateMedia({ reducedMotion: "reduce" });
    let catalogAvailable = false;
    let revision = 1;
    let pendingTraffic;
    let sourceAvailable = true;
    let settings = { maxMB: 1024, retentionHours: 24 };
    const requests = [];
    const writes = [];
    const now = Date.now();
    const officeID = "01550000-1111-4222-8333-444455556666";
    const events = Array.from({ length: 10020 }, (_, i) => ({
      id: String(i),
      time: new Date(now - i * 100).toISOString(),
      protocol: i % 2 ? "TCP" : "UDP",
      domain: "flow-" + i + ".example",
      address: "192.0.2.1",
      country: i % 2 ? undefined : "RU",
      port: 443,
      kind: "observed",
      connection: officeID,
      reason: "outbound[dns-" + officeID + "]",
      namespace: "test",
      networkInterface: "ppp0",
    }));
    events[0].kind = "unconfirmed";
    events[0].connection = "keenetic-uplink";
    delete events[0].namespace;
    delete events[0].networkInterface;
    events[1].kind = "unconfirmed";
    delete events[1].connection;
    delete events[1].namespace;
    delete events[1].networkInterface;
    events[2].kind = "blocked";
    events[2].blockReason = "Правило sing-box отклонило поток";
    delete events[2].connection;
    delete events[2].namespace;
    delete events[2].networkInterface;
    events[600].country = "SE";
    events[601].country = "CH";
    const names = new Intl.DisplayNames("ru", { type: "region" });
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname === "/api/traffic/settings") {
        if (route.request().method() === "PUT") {
          const { expected, proposed } = route.request().postDataJSON();
          writes.push({ expected, proposed });
          if (
            expected?.maxMB !== settings.maxMB ||
            expected?.retentionHours !== settings.retentionHours
          )
            return route.fulfill({ status: 409, json: { status: 409 } });
          settings = proposed;
        }
        return route.fulfill({ json: settings });
      }
      if (url.pathname === "/api/traffic") {
        const q = url.searchParams;
        requests.push(Object.fromEntries(q));
        if (pendingTraffic) await pendingTraffic;
        const matching = events.filter(
          (e) =>
            (!q.has("query") || e.domain.includes(q.get("query"))) &&
            (!q.has("country") ||
              (e.country ? names.of(e.country) : "Не определена")
                .toLowerCase()
                .includes(q.get("country").toLowerCase())) &&
            (!q.has("protocol") || e.protocol === q.get("protocol")) &&
            (!q.has("output") ||
              (q.get("output").startsWith("connection:") &&
                e.connection === q.get("output").slice("connection:".length)) ||
              (q.get("output") === "blocked" && e.kind === "blocked") ||
              (q.get("output") === "unknown" &&
                e.kind === "unconfirmed" &&
                !e.connection)) &&
            Date.parse(e.time) >= Date.parse(q.get("from")),
        );
        const offset = Number(q.get("offset"));
        const limit = Number(q.get("limit"));
        assert.ok(limit > 0 && limit <= 500);
        return route.fulfill({
          json: {
            total: matching.length,
            events: matching.slice(offset, offset + limit),
            snapshot: q.get("snapshot") || String(revision),
            outputs: [officeID, "keenetic-uplink"],
            lost: 16,
            sourceAvailable,
            lastInterruption: new Date(now - 60000).toISOString(),
          },
        });
      }
      if (url.pathname === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (url.pathname === "/api/hysteria2") return route.fulfill({ json: [] });
      if (url.pathname === "/api/awg-underlays" && !catalogAvailable)
        return route.fulfill({ status: 503 });
      if (url.pathname === "/api/awg-underlays")
        return route.fulfill({
          json: [
            { id: officeID, name: "Офис", type: "wireguard" },
            { id: "keenetic-direct", name: "Провайдер", type: "direct" },
            { id: "keenetic-uplink", name: "Мой провайдер", type: "direct" },
          ],
        });
      if (url.pathname.startsWith("/api/"))
        throw Error("Unexpected request " + url.pathname);
      return route.fulfill({
        path: fileURLToPath(
          new URL(
            "../../dist/hestia/browser/" +
              (url.pathname.slice(1) || "index.html"),
            import.meta.url,
          ),
        ),
      });
    });
    await page.clock.install();
    await page.goto("http://127.0.0.1/#/traffic");
    await page.addStyleTag({
      content:
        "*, *::before, *::after { animation-duration: 0s !important; transition-duration: 0s !important; }",
    });
    await page
      .getByText("Подключение недоступно", { exact: true })
      .first()
      .waitFor();
    const auto = page.getByRole("switch", {
      name: "Автообновление",
      exact: true,
    });
    assert.equal(await auto.isChecked(), true);
    await auto.click();
    catalogAvailable = true;
    await page.getByRole("button", { name: "Обновить журнал" }).click();
    await page.getByText("Офис", { exact: true }).first().waitFor();
    await page
      .getByRole("button", { name: "flow-0.example", exact: true })
      .waitFor();
    assert.equal(
      await page.getByText(/Сбор возобновлён|Потеряно событий/).count(),
      0,
    );
    assert.equal(
      Date.parse(requests[0].until) - Date.parse(requests[0].from),
      300000,
    );
    await page.getByRole("combobox", { name: "Период" }).click();
    await page
      .getByRole("option", { name: "Последний час", exact: true })
      .click();
    await page.getByRole("columnheader", { name: "Страна" }).waitFor();
    await page
      .getByRole("cell", { name: "Россия", exact: true })
      .first()
      .waitFor();
    await page.getByRole("cell", { name: "Не определена" }).first().waitFor();
    await page
      .getByRole("cell", { name: "Мой провайдер", exact: true })
      .waitFor();
    await page
      .getByRole("cell", { name: "Не определено", exact: true })
      .waitFor();
    const scroller = page.locator(".p-virtualscroller");
    const initialHeight = (await scroller.boundingBox()).height;
    await page.setViewportSize({ width: 1280, height: 1080 });
    await page.waitForFunction(
      (height) =>
        document.querySelector(".p-virtualscroller").clientHeight >=
        height + 340,
      initialHeight,
    );
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollHeight <= innerHeight + 1,
      ),
    );
    await page.getByRole("combobox", { name: "Выход", exact: true }).click();
    await page.getByRole("option", { name: "Офис", exact: true }).waitFor();
    await page
      .getByRole("option", { name: "Мой провайдер", exact: true })
      .waitFor();
    await page
      .getByRole("option", { name: "Не определено", exact: true })
      .waitFor();
    await page
      .getByRole("option", { name: "Заблокировано", exact: true })
      .waitFor();
    assert.equal(
      await page.getByRole("option", { name: "Офис", exact: true }).count(),
      1,
    );
    await page.getByRole("option", { name: "Провайдер", exact: true }).click();
    await page
      .getByText("За выбранный период подходящих записей нет.")
      .waitFor();
    assert.equal(requests.at(-1).output, "connection:keenetic-direct");
    await page.getByRole("combobox", { name: "Выход", exact: true }).click();
    await page.getByRole("option", { name: "Все выходы", exact: true }).click();
    await page
      .getByRole("button", { name: "flow-0.example", exact: true })
      .waitFor();
    await page.getByRole("combobox", { name: "Выход", exact: true }).click();
    await page
      .getByRole("option", { name: "Не определено", exact: true })
      .click();
    await page
      .getByRole("button", { name: "flow-1.example", exact: true })
      .waitFor();
    await page.getByText("Найдено событий: 1", { exact: true }).waitFor();
    assert.equal(requests.at(-1).output, "unknown");
    await page.getByRole("combobox", { name: "Выход", exact: true }).click();
    await page.getByRole("option", { name: "Все выходы", exact: true }).click();
    await page.getByRole("button", { name: "Старее" }).click();
    await page
      .getByRole("button", { name: "flow-10000.example", exact: true })
      .waitFor();
    await page.getByRole("button", { name: "Новее" }).click();
    await page
      .getByRole("button", { name: "flow-0.example", exact: true })
      .waitFor();
    await page
      .locator(".p-virtualscroller")
      .evaluate((el) => el.scrollTo({ top: el.scrollHeight }));
    await page
      .getByRole("button", { name: "flow-9999.example", exact: true })
      .click();
    await page
      .getByRole("dialog")
      .getByText("ppp0", { exact: false })
      .waitFor();
    await page
      .getByRole("dialog")
      .getByText("outbound[dns-Офис]", { exact: true })
      .waitFor();
    assert.ok(!(await page.locator("body").innerText()).includes(officeID));
    await page.keyboard.press("Escape");
    assert.ok((await page.locator("tbody tr").count()) < 500);
    assert.ok(
      requests.some((q) => Number(q.offset) > 500 && q.snapshot === "1"),
    );
    const country = page.getByRole("searchbox", { name: "Страна" });
    await country.fill("шв");
    await page.getByRole("cell", { name: "Швеция", exact: true }).waitFor();
    await page.getByRole("cell", { name: "Швейцария", exact: true }).waitFor();
    await page.getByText("Найдено событий: 2", { exact: true }).waitFor();
    assert.equal(requests.at(-1).offset, "0");
    await page.getByRole("button", { name: "Обновить журнал" }).click();
    await page.getByText("Найдено событий: 2", { exact: true }).waitFor();
    assert.equal(requests.at(-1).country, "шв");
    await country.fill("");
    await page
      .getByRole("searchbox", { name: "Домен или IP" })
      .fill("flow-119");
    await page.getByRole("combobox", { name: "Протокол", exact: true }).click();
    await page.getByRole("option", { name: "UDP", exact: true }).click();
    await page.getByRole("combobox", { name: "Выход", exact: true }).click();
    await page.getByRole("option", { name: "Офис", exact: true }).click();
    await page
      .getByRole("button", { name: "flow-1192.example", exact: true })
      .waitFor();
    await page.getByRole("combobox", { name: "Период" }).click();
    await page.getByRole("option", { name: "Последние 5 минут" }).click();
    await page
      .getByRole("button", { name: "flow-1192.example", exact: true })
      .waitFor();
    revision++;
    events.unshift({
      ...events[0],
      id: "new",
      domain: "flow-119-new.example",
      time: new Date().toISOString(),
      kind: "observed",
      connection: officeID,
      namespace: "test",
      networkInterface: "ppp0",
    });
    await page.getByRole("button", { name: "Обновить журнал" }).click();
    await page
      .getByRole("button", { name: "flow-119-new.example", exact: true })
      .waitFor();
    assert.equal(
      Date.parse(requests.at(-1).until) - Date.parse(requests.at(-1).from),
      300000,
    );
    assert.deepEqual(
      [
        requests.at(-1).query,
        requests.at(-1).protocol,
        requests.at(-1).output,
        requests.at(-1).snapshot,
      ],
      ["flow-119", "UDP", "connection:" + officeID, undefined],
    );
    await auto.click();
    assert.equal(await auto.isChecked(), true);
    await page
      .getByRole("button", { name: "flow-119-new.example", exact: true })
      .click();
    await page.getByRole("dialog").waitFor();
    const beforeAuto = requests.length;
    let releaseTraffic;
    pendingTraffic = new Promise((resolve) => {
      releaseTraffic = resolve;
    });
    await page.clock.runFor(5000);
    await page.getByText("Загрузка событий…", { exact: true }).waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "flow-119-new.example", exact: true })
        .isVisible(),
      true,
    );
    await page.clock.runFor(5000);
    assert.equal(requests.length, beforeAuto + 1);
    releaseTraffic();
    pendingTraffic = undefined;
    await page.waitForFunction(
      () => !document.body.innerText.includes("Загрузка событий…"),
    );
    assert.equal(requests.length, beforeAuto + 1);
    assert.equal(await page.getByRole("dialog").count(), 1);
    await page.keyboard.press("Escape");
    assert.equal(requests.at(-1).query, "flow-119");
    assert.equal(requests.at(-1).protocol, "UDP");
    assert.equal(requests.at(-1).snapshot, undefined);
    await auto.click();
    const afterAuto = requests.length;
    await page.clock.runFor(10000);
    assert.equal(requests.length, afterAuto);
    await page.getByRole("button", { name: "Настройки журнала" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Объём, МБ").fill("512");
    await dialog.getByLabel("Срок хранения, ч").fill("1");
    settings = { maxMB: 2048, retentionHours: 96 };
    await dialog.getByRole("button", { name: "Сохранить" }).click();
    await dialog
      .locator("p-toast")
      .getByText(/Настройки изменились на шлюзе/)
      .waitFor();
    assert.deepEqual(writes, [
      {
        expected: { maxMB: 1024, retentionHours: 24 },
        proposed: { maxMB: 512, retentionHours: 1 },
      },
    ]);
    assert.deepEqual(settings, { maxMB: 2048, retentionHours: 96 });
    await dialog
      .getByRole("button", { name: "Загрузить актуальные настройки" })
      .click();
    await dialog.getByLabel("Объём, МБ").waitFor();
    assert.equal(await dialog.getByLabel("Объём, МБ").inputValue(), "2048");
    assert.equal(
      await dialog.getByLabel("Срок хранения, ч").inputValue(),
      "96",
    );
    assert.equal(writes.length, 1);
    await dialog.getByLabel("Объём, МБ").fill("512");
    await dialog.getByLabel("Срок хранения, ч").fill("72");
    await dialog.getByRole("button", { name: "Сохранить" }).click();
    await dialog.waitFor({ state: "hidden" });
    await page
      .locator("p-toast")
      .getByText("Настройки журнала сохранены.")
      .waitFor();
    assert.deepEqual(settings, { maxMB: 512, retentionHours: 72 });
    sourceAvailable = false;
    await page.getByRole("button", { name: "Обновить журнал" }).click();
    await page.getByText(/Сбор приостановлен.*Нет связи/s).waitFor();
    assert.equal(await page.getByText(/Сбор возобновлён/).count(), 0);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForFunction(
      () => document.documentElement.scrollWidth <= innerWidth,
    );
    assert.ok((await scroller.boundingBox()).height > 240);
    assert.ok(
      await page.evaluate(
        () => document.documentElement.scrollHeight <= innerHeight + 1,
      ),
    );
  } finally {
    await browser.close();
  }
});
