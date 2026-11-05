import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

test("quality page displays all ranked groups, keeps a measured zero, and persists each individual modal action", async () => {
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
  let catalogAvailable = false;
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
      if (path === "/api/hysteria2") return route.fulfill({ json: [] });
      if (path === "/api/awg-underlays" && !catalogAvailable)
        return route.fulfill({ status: 503 });
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
            overall: id === "b" ? 85.47 : null,
            checks: settings.checks.map((check) =>
              id === "b" && check.protocol === "ICMP"
                ? {
                    protocol: "ICMP",
                    unsupported: true,
                    samples: 0,
                    successes: 0,
                    localErrors: 0,
                    score: null,
                    targets: [],
                  }
                : {
                    protocol: check.protocol,
                    samples: id === "b" ? 1 : 0,
                    successes: 0,
                    localErrors: 0,
                    score:
                      id === "b" ? (check.protocol === "TCP" ? 85.5 : 0) : null,
                    targets: check.targets.map((target) => ({
                      target,
                      samples: id === "b" ? 1 : 0,
                      successes: 0,
                      localErrors: 0,
                      dnsErrors: 0,
                      score: id === "b" ? 0 : null,
                    })),
                  },
            ),
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
      if (path.startsWith("/api/quality/checks/")) {
        const protocol = path.split("/").at(-1);
        const method = route.request().method();
        if (method === "PUT") {
          const input = route.request().postDataJSON();
          let check = input;
          if (protocol === "TCP") {
            if (input.targets.includes("missing.example"))
              return route.fulfill({
                status: 422,
                json: {
                  detail: "Ошибка DNS для missing.example: имя не найдено.",
                },
              });
            assert.deepEqual(input.targets, [
              "example.org",
              "8.8.8.8",
              "example.org:8443",
            ]);
            check = {
              ...input,
              targets: ["1.1.1.1:443", "8.8.8.8:443", "1.1.1.1:8443"],
            };
          }
          assert.equal(protocol, check.protocol);
          const exists = settings.checks.some((c) => c.protocol === protocol);
          settings = {
            ...settings,
            checks: exists
              ? settings.checks.map((c) =>
                  c.protocol === protocol ? check : c,
                )
              : [...settings.checks, check],
          };
          writes.push({ method, protocol, check });
        } else if (method === "DELETE") {
          settings = {
            ...settings,
            checks: settings.checks.filter((c) => c.protocol !== protocol),
          };
          writes.push({ method, protocol });
        } else throw new Error("Unexpected check operation " + method);
        return route.fulfill({ json: settings });
      }
      if (
        path === "/api/quality/window" &&
        route.request().method() === "PUT"
      ) {
        const body = route.request().postDataJSON();
        assert.deepEqual(Object.keys(body), ["windowMinutes"]);
        settings = { ...settings, ...body };
        writes.push(body);
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
    await page.getByRole("rowheader", { name: "b", exact: true }).waitFor();
    assert.deepEqual(
      await page.getByRole("heading", { level: 2 }).allTextContents(),
      ["Группы подключений", "Проверки"],
    );
    const menu = page.getByRole("navigation", { name: "Основная навигация" });
    const links = menu.getByRole("link");
    const menuLabels = [
      "Качество связи",
      "Журнал трафика",
      "Подключения",
      "Группы подключений",
      "Доменные списки",
      "Маршруты по странам",
      "DNS",
    ];
    assert.equal(await links.count(), menuLabels.length);
    await links.first().focus();
    for (const [index, label] of menuLabels.entries()) {
      if (index > 0) await page.keyboard.press("Tab");
      assert.equal(
        await menu.locator("a:focus").getAttribute("aria-label"),
        label,
      );
    }
    catalogAvailable = true;
    await page.getByRole("button", { name: "Обновить", exact: true }).click();
    await page.getByRole("rowheader", { name: "Бета", exact: true }).waitFor();
    await page.getByRole("heading", { name: "Пустая группа" }).waitFor();
    const table = page.getByRole("table").first();
    const first = table.getByRole("row").nth(1);
    assert.match(await first.innerText(), /Бета/);
    assert.match(await first.innerText(), /Активно/);
    await table
      .getByRole("columnheader", { name: "Качество связи", exact: true })
      .waitFor();
    for (const score of ["0%", "86%", "85%"])
      await first.getByText(score, { exact: true }).waitFor();
    assert.match(await table.getByRole("row").nth(2).innerText(), /Нет данных/);
    const open = async (name) => {
      await page.getByRole("button", { name, exact: true }).click();
      const dialog = page.getByRole("dialog");
      await dialog.waitFor();
      assert.equal(await dialog.count(), 1);
      return dialog;
    };
    const edit = await open("Редактировать проверку UDP");
    assert.equal(
      await edit.getByLabel("Домен для DNS-запроса").inputValue(),
      udp.dnsName,
    );
    assert.equal(await edit.getByLabel("Цели").count(), 1);
    assert.equal(await edit.getByText(/TCP|Окно оценки/).count(), 0);
    await edit.getByLabel("Интервал, с").fill("15");
    await edit.getByRole("button", { name: "Сохранить" }).click();
    await page.getByText("Настройки проверок сохранены.").first().waitFor();
    await page.getByRole("dialog").waitFor({ state: "hidden" });
    assert.deepEqual(writes, [
      {
        method: "PUT",
        protocol: "UDP",
        check: { ...udp, intervalSeconds: 15 },
      },
    ]);
    assert.deepEqual(settings.checks[1], tcp);

    for (const check of [
      { protocol: "ICMP", targets: ["8.8.8.8"] },
      { protocol: "DNS", targets: ["8.8.8.8:53"], dnsName: "example.org" },
      {
        protocol: "HTTPS",
        targets: ["1.1.1.1:443"],
        serverName: "example.org",
        requestPath: "/health",
      },
      {
        protocol: "HTTP3",
        targets: ["1.1.1.1:443"],
        serverName: "example.org",
        requestPath: "/health?version=3",
      },
    ]) {
      const label = check.protocol === "HTTP3" ? "HTTP/3" : check.protocol;
      const dialog = await open("Добавить " + label);
      await dialog.getByLabel("Цели").fill(check.targets.join("\n"));
      if (check.dnsName)
        await dialog.getByLabel("Домен для DNS-запроса").fill(check.dnsName);
      else
        assert.equal(
          await dialog.getByLabel("Домен для DNS-запроса").count(),
          0,
        );
      if (check.serverName) {
        await dialog.getByLabel("Имя сервера TLS").fill(check.serverName);
        await dialog.getByLabel("Путь запроса").fill(check.requestPath);
      }
      await dialog.getByRole("button", { name: "Сохранить" }).click();
      await page
        .getByRole("heading", {
          name: "Проверка " + label,
          exact: true,
        })
        .waitFor();
      assert.deepEqual(writes.at(-1), {
        method: "PUT",
        protocol: check.protocol,
        check: { ...check, intervalSeconds: 30, timeoutSeconds: 3 },
      });
    }
    const unsupported = first.getByRole("cell", {
      name: "не поддерживается",
      exact: true,
    });
    await unsupported.waitFor();
    assert.equal(await unsupported.locator("details").count(), 0);
    await first.getByText("85%", { exact: true }).waitFor();
    for (const check of settings.checks) {
      const label = check.protocol === "HTTP3" ? "HTTP/3" : check.protocol;
      const dialog = await open("Редактировать проверку " + label);
      assert.equal(
        await dialog.getByLabel("Цели").inputValue(),
        check.targets.join("\n"),
      );
      assert.equal(
        await dialog.getByLabel("Домен для DNS-запроса").count(),
        check.dnsName ? 1 : 0,
      );
      assert.equal(
        await dialog.getByLabel("Имя сервера TLS").count(),
        check.serverName ? 1 : 0,
      );
      await page.keyboard.press("Escape");
      await dialog.waitFor({ state: "hidden" });
    }
    const deleteDialog = await open("Удалить проверку UDP");
    await deleteDialog.getByRole("button", { name: "Отмена" }).click();
    assert.equal(writes.length, 5);
    await (
      await open("Удалить проверку UDP")
    )
      .getByRole("button", { name: "Удалить", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Добавить UDP", exact: true })
      .waitFor();
    assert.deepEqual(writes.at(-1), { method: "DELETE", protocol: "UDP" });

    const windowDialog = await open("Редактировать окно оценки");
    assert.equal(await windowDialog.getByLabel("Цели").count(), 0);
    await windowDialog.getByLabel("Окно оценки, мин").fill("90");
    await windowDialog.getByRole("button", { name: "Сохранить" }).click();
    await page.getByText("Окно оценки: 90 мин").waitFor();
    assert.deepEqual(writes.at(-1), { windowMinutes: 90 });
    await page.reload();
    await page.getByText("Окно оценки: 90 мин").waitFor();
    confirmed = false;
    await page.getByRole("button", { name: "Обновить", exact: true }).click();
    await first.getByText("Активный выход неизвестен").waitFor();
    fresh = false;
    confirmed = true;
    await page.getByRole("button", { name: "Обновить", exact: true }).click();
    await page.locator("time").waitFor({ state: "detached" });
    await first.getByText("Активный выход неизвестен").waitFor();
    assert.equal(writes.length, 7);

    const tcpDialog = await open("Редактировать проверку TCP");
    const targets = tcpDialog.getByLabel("Цели");
    await targets.fill("8.8.8.8\nmissing.example");
    await tcpDialog.getByRole("button", { name: "Сохранить" }).click();
    await page
      .getByText("Ошибка DNS для missing.example: имя не найдено.")
      .first()
      .waitFor();
    const targetField = await targets.elementHandle();
    await page.waitForFunction(
      (field) => document.activeElement === field,
      targetField,
    );
    assert.equal(await targets.inputValue(), "8.8.8.8\nmissing.example");
    assert.deepEqual(
      settings.checks.find((c) => c.protocol === "TCP"),
      tcp,
    );
    await targets.fill("example.org\n8.8.8.8\nexample.org:8443");
    await tcpDialog.getByRole("button", { name: "Сохранить" }).click();
    await page.waitForFunction(
      (field) =>
        document.activeElement === field &&
        field.value === "1.1.1.1:443\n8.8.8.8:443\n1.1.1.1:8443",
      targetField,
    );
    await page.keyboard.press("Escape");
    await tcpDialog.waitFor({ state: "hidden" });
    const editTCP = page.getByRole("button", {
      name: "Редактировать проверку TCP",
      exact: true,
    });
    await page.waitForFunction(
      (button) => document.activeElement === button,
      await editTCP.elementHandle(),
    );
    assert.equal(writes.length, 8);
  } finally {
    await browser.close();
  }
});
