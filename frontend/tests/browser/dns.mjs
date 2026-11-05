import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

/** Exercises DNS settings and all three visible lists against a revisioned gateway fixture on a mobile viewport. */
test("DNS edits independent lists, rejects stale writes and preserves draft settings", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({
      viewport: { width: 360, height: 800 },
    });
    page.setDefaultTimeout(6000);
    let revision = 0,
      available = true,
      reportRows = true;
    let clientUdp = {
      attempts: 1,
      retriedAttempts: 0,
      unclassifiedAttempts: 0,
    };
    let policy = {
      settings: {
        automaticEnabled: true,
        intervalMinutes: 10,
        retentionSeconds: 300,
        serveStale: false,
        staleWindowSeconds: 0,
        threshold: 5,
        windowHours: 24,
      },
      manual: [],
      exclusions: [],
    };
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/dns/policy") {
        if (route.request().method() === "PUT") {
          const write = route.request().postDataJSON();
          if (write.expectedRevision !== revision)
            return route.fulfill({ status: 409, json: {} });
          policy = write.policy;
          revision++;
        }
        return route.fulfill({ json: { revision, policy } });
      }
      if (path === "/api/dns/warm") {
        if (!available) return route.fulfill({ status: 503, json: {} });
        const automatic =
          reportRows &&
          policy.settings.automaticEnabled &&
          !policy.exclusions.includes("cdn.example")
            ? [{ domain: "cdn.example", clientRequests: 7 }]
            : [];
        return route.fulfill({
          json: {
            clientUdp: reportRows
              ? clientUdp
              : { attempts: 0, retriedAttempts: 0, unclassifiedAttempts: 0 },
            observedAt: new Date().toISOString(),
            policyRevision: revision,
            automatic,
          },
        });
      }
      if (path === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (path.startsWith("/api/")) return route.fulfill({ json: [] });
      return route.fulfill({
        path: fileURLToPath(
          new URL(
            "../../dist/hestia/browser/" + (path.slice(1) || "index.html"),
            import.meta.url,
          ),
        ),
      });
    });
    await page.goto("http://127.0.0.1/#/dns");
    const automatic = page.getByRole("region", {
      name: "Автоматически добавленные",
    });
    const excluded = page.getByRole("region", {
      name: "Чёрный список автопрогрева",
    });
    const manual = page.getByRole("region", { name: "Добавленные вручную" });
    await automatic.getByText("cdn.example", { exact: true }).waitFor();
    await automatic
      .getByText(/UDP без замеченного повтора — 100\s*%/)
      .waitFor();
    clientUdp = { attempts: 3, retriedAttempts: 1, unclassifiedAttempts: 1 };
    await page.reload();
    await automatic.getByText(/UDP без замеченного повтора — 50\s*%/).waitFor();
    await automatic
      .getByText(/всего попыток 3, потребовали повтора 1.*Вне расчёта 1/s)
      .waitFor();
    assert.deepEqual(
      (await page.locator("hestia-dns-names h2").allTextContents()).map(
        (heading) => heading.trim(),
      ),
      [
        "Автоматически добавленные",
        "Чёрный список автопрогрева",
        "Добавленные вручную",
      ],
    );
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= window.innerWidth,
      ),
      true,
    );
    const threshold = page.getByRole("spinbutton", {
      name: "Порог запросов (N)",
    });
    // Even a first save equal to the displayed defaults creates durable revision one.
    const staleMode = page.getByRole("switch", {
      name: "Разрешить истёкший ответ при временном сбое DNS",
    });
    await staleMode.press("Space");
    const staleWindow = page.getByRole("spinbutton", {
      name: "Окно выдачи после TTL, с",
    });
    await staleWindow.waitFor();
    await staleMode.press("Space");
    await staleWindow.waitFor({ state: "hidden" });
    await page
      .getByRole("button", { name: "Сохранить настройки" })
      .press("Enter");
    await page.getByText("Настройки DNS сохранены.").waitFor();
    assert.equal(revision, 1);
    await threshold.fill("6");
    await threshold.press("Tab");
    const manualInput = manual.getByRole("textbox");
    await manualInput.fill("CDN.example.");
    await manualInput.press("Enter");
    await manual.getByText("cdn.example", { exact: true }).waitFor();
    assert.equal(policy.settings.threshold, 5);
    assert.equal(await threshold.inputValue(), "6");
    await automatic
      .getByRole("button", { name: "В чёрный список: cdn.example" })
      .press("Enter");
    await excluded.getByText("cdn.example", { exact: true }).waitFor();
    await automatic
      .getByText("Автоматически добавленных доменов пока нет.")
      .waitFor();
    await manual.getByText("Исключён из автопрогрева").waitFor();
    await excluded
      .getByRole("button", { name: "Снять исключение: cdn.example" })
      .press("Enter");
    await automatic.getByText("cdn.example", { exact: true }).waitFor();
    const excludeInput = excluded.getByRole("textbox");
    await excludeInput.fill("early.example");
    await excludeInput.press("Enter");
    await excluded
      .getByRole("button", { name: "Изменить исключение: early.example" })
      .press("Enter");
    await excluded
      .getByRole("button", { name: "Сохранить исключение" })
      .waitFor();
    assert.equal(await excludeInput.inputValue(), "early.example");
    await excludeInput.fill("changed.example");
    await excludeInput.press("Enter");
    await excluded.getByText("changed.example", { exact: true }).waitFor();
    assert.deepEqual(policy.exclusions, ["changed.example"]);
    await excludeInput.fill("changed.example");
    await excludeInput.press("Enter");
    await excluded.getByText("Такой домен уже есть в списке.").waitFor();
    await manual
      .getByRole("button", { name: "Удалить из ручного списка: cdn.example" })
      .press("Enter");
    await manual.getByText("Домены вручную ещё не добавлены.").waitFor();
    await automatic.getByText("cdn.example", { exact: true }).waitFor();
    await page
      .getByRole("button", { name: "Сохранить настройки" })
      .press("Enter");
    await page.getByText("Настройки DNS сохранены.").waitFor();
    assert.equal(policy.settings.threshold, 6);
    revision++;
    await manualInput.fill("conflict.example");
    await manualInput.press("Enter");
    await page.getByText(/Настройки изменились/).waitFor();
    assert.deepEqual(policy.manual, []);
    available = false;
    await page
      .getByRole("button", { name: "Перечитать настройки со шлюза" })
      .press("Enter");
    await automatic
      .getByText("Сведения об автоматическом прогреве недоступны.")
      .waitFor();
    await excluded.getByText("changed.example", { exact: true }).waitFor();
    available = true;
    reportRows = false;
    await page.reload();
    await automatic
      .getByText("Автоматически добавленных доменов пока нет.")
      .waitFor();
    await automatic
      .getByText("С запуска службы UDP-запросов от маршрутизатора ещё не было.")
      .waitFor();
    await excluded.getByText("changed.example", { exact: true }).waitFor();
  } finally {
    await browser.close();
  }
});
