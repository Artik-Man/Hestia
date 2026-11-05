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
    page.setDefaultTimeout(5000);
    let revision = 1;
    let settings = { maxMB: 1024, retentionHours: 24 };
    const requests = [];
    const writes = [];
    const now = Date.now();
    const events = Array.from({ length: 10020 }, (_, i) => ({
      id: String(i),
      time: new Date(now - i * 100).toISOString(),
      protocol: i % 2 ? "TCP" : "UDP",
      domain: "flow-" + i + ".example",
      address: "192.0.2.1",
      port: 443,
      kind: "observed",
      connection: i % 4 ? "FI-1" : "RU-1",
      namespace: "test",
      networkInterface: "ppp0",
    }));
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
        const matching = events.filter(
          (e) =>
            (!q.has("query") || e.domain.includes(q.get("query"))) &&
            (!q.has("protocol") || e.protocol === q.get("protocol")) &&
            (!q.has("output") ||
              "connection:" + e.connection === q.get("output")) &&
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
            outputs: ["FI-1", "RU-1"],
            lost: 0,
            sourceAvailable: true,
            lastInterruption: new Date(now - 60000).toISOString(),
          },
        });
      }
      if (url.pathname === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (url.pathname === "/api/awg-underlays")
        return route.fulfill({ json: [] });
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
    await page.goto("http://127.0.0.1/#/traffic");
    await page
      .getByRole("button", { name: "flow-0.example", exact: true })
      .waitFor();
    await page.getByText(/Последний перерыв сбора/).waitFor();
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
    await page.keyboard.press("Escape");
    assert.ok((await page.locator("tbody tr").count()) < 500);
    assert.ok(
      requests.some((q) => Number(q.offset) > 500 && q.snapshot === "1"),
    );
    await page.getByRole("searchbox").fill("flow-119");
    await page.getByRole("combobox", { name: "Протокол", exact: true }).click();
    await page.getByRole("option", { name: "UDP", exact: true }).click();
    await page.getByRole("combobox", { name: "Выход", exact: true }).click();
    await page.getByRole("option", { name: "RU-1", exact: true }).click();
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
      ["flow-119", "UDP", "connection:RU-1", undefined],
    );
    await page.getByRole("button", { name: "Настройки журнала" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Объём, МБ").fill("512");
    await dialog.getByLabel("Срок хранения, ч").fill("1");
    settings = { maxMB: 2048, retentionHours: 96 };
    await dialog.getByRole("button", { name: "Сохранить" }).click();
    await dialog.getByText(/Настройки изменились на шлюзе/).waitFor();
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
    assert.deepEqual(settings, { maxMB: 512, retentionHours: 72 });
  } finally {
    await browser.close();
  }
});
