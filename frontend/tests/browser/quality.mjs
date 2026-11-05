import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

test("quality page displays all ranked groups, keeps a measured zero, and persists staged settings", async () => {
  const udp = {
    protocol: "UDP",
    targets: ["1.1.1.1:53", "8.8.8.8:53"],
    dnsName: "example.com",
    intervalSeconds: 30,
    timeoutSeconds: 3,
  };
  const tcp = {
    protocol: "TCP",
    targets: ["1.1.1.1:443"],
    intervalSeconds: 30,
    timeoutSeconds: 3,
  };
  let settings = { windowMinutes: 60, checks: [udp, tcp] };
  const writes = [];
  let confirmed = true;
  let fresh = true;
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(5000);
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (path === "/api/awg-underlays")
        return route.fulfill({
          json: [
            { id: "a", name: "Альфа", type: "direct" },
            { id: "b", name: "Бета", type: "wireguard" },
          ],
        });
      if (path === "/api/quality") {
        const connections = ["b", "a"].map((id) => ({
          id,
          available: true,
          active: confirmed && id === "b",
          result: {
            overall: id === "b" ? 0 : null,
            checks: settings.checks.map((check) => ({
              protocol: check.protocol,
              samples: id === "b" ? 1 : 0,
              successes: 0,
              localErrors: 0,
              score: id === "b" ? 0 : null,
              targets: check.targets.map((target) => ({
                target,
                samples: id === "b" ? 1 : 0,
                successes: 0,
                localErrors: 0,
                dnsErrors: 0,
                score: id === "b" ? 0 : null,
              })),
            })),
          },
        }));
        return route.fulfill({
          json: {
            settings,
            capturedAt: fresh ? new Date().toISOString() : "",
            groups: [
              { id: "fi", name: "Финляндия", connections },
              { id: "extra", name: "Пустая группа", connections: [] },
            ],
          },
        });
      }
      if (
        path === "/api/quality/settings" &&
        route.request().method() === "PUT"
      ) {
        settings = route.request().postDataJSON();
        writes.push(settings);
        return route.fulfill({ json: settings });
      }
      if (path.startsWith("/api/"))
        throw new Error("Unexpected API request " + path);
      return route.fulfill({
        path: fileURLToPath(
          new URL(
            "../../dist/hestia/browser/" + (path.slice(1) || "index.html"),
            import.meta.url,
          ),
        ),
      });
    });
    await page.goto("http://127.0.0.1/#/quality");
    await page.getByRole("heading", { name: "Пустая группа" }).waitFor();
    const table = page.getByRole("table").first();
    const first = table.getByRole("row").nth(1);
    assert.match(await first.innerText(), /Бета/);
    assert.match(await first.innerText(), /Активно/);
    assert.match(await first.innerText(), /0\s*\/\s*100/);
    assert.match(await table.getByRole("row").nth(2).innerText(), /Нет данных/);
    await page
      .getByRole("button", { name: "Удалить проверку UDP", exact: true })
      .click();
    await page.getByRole("button", { name: "Отмена", exact: true }).click();
    assert.equal(writes.length, 0);
    await page
      .getByRole("button", { name: "Удалить проверку UDP", exact: true })
      .click();
    await page.getByLabel("Окно оценки, мин").fill("90");
    await page.getByRole("button", { name: "Сохранить", exact: true }).click();
    await page.getByText("Настройки проверок сохранены.").waitFor();
    assert.deepEqual(writes, [{ windowMinutes: 90, checks: [tcp] }]);
    await page.reload();
    await page.getByText("Окно оценки: 90 мин").waitFor();
    assert.equal(
      await page.getByRole("heading", { name: "Проверка UDP" }).count(),
      0,
    );
    await page
      .getByRole("button", { name: "Редактировать настройки проверок" })
      .click();
    await page.getByRole("button", { name: "Добавить UDP" }).click();
    const newUDP = page.getByRole("group", {
      name: "Проверка UDP",
      exact: true,
    });
    await newUDP.getByLabel("Цели").fill(udp.targets.join("\n"));
    await page.getByRole("button", { name: "Сохранить", exact: true }).click();
    await page.getByRole("heading", { name: "Проверка UDP" }).waitFor();
    confirmed = false;
    await page.getByRole("button", { name: "Обновить", exact: true }).click();
    await first.getByText("Активный выход неизвестен").waitFor();
    fresh = false;
    confirmed = true;
    await page.getByRole("button", { name: "Обновить", exact: true }).click();
    await page.locator("time").waitFor({ state: "detached" });
    await first.getByText("Активный выход неизвестен").waitFor();
    assert.deepEqual(writes.at(-1), { windowMinutes: 90, checks: [tcp, udp] });
  } finally {
    await browser.close();
  }
});
