import assert from "node:assert/strict";
import test from "node:test";
import { chromium } from "playwright";

/** Exercise the deployed Angular entry point against a fresh real Go policy store. */
test(
  "DNS persists separate manual and excluded domains across reloads and reports concurrent edits",
  { timeout: 45000 },
  async () => {
    const url = new URL(process.env.HESTIA_DNS_BROWSER_FIXTURE);
    assert.equal(url.hostname, "127.0.0.1");
    const browser = await chromium.launch({
      executablePath: process.env.CHROME_BIN,
    });
    try {
      const page = await browser.newPage();
      page.setDefaultTimeout(6000);
      await page.goto(new URL("/#/dns", url).href);
      const auto = page.getByRole("region", {
        name: "Автоматически добавленные",
      });
      const excluded = page.getByRole("region", {
        name: "Чёрный список автопрогрева",
      });
      const manual = page.getByRole("region", { name: "Добавленные вручную" });
      await auto
        .getByText("Сведения об автоматическом прогреве недоступны.")
        .waitFor();
      const autoSwitch = page.getByRole("switch", {
        name: "Автоматически добавлять частые домены",
      });
      await autoSwitch.press("Space");
      await autoSwitch.press("Space");
      await page.getByRole("button", { name: "Сохранить настройки" }).click();
      await page.getByText("Настройки DNS сохранены.").waitFor();
      const retention = page.getByRole("spinbutton", {
        name: "Хранить ответ после TTL, с",
      });
      await retention.fill("120");
      await retention.press("Tab");
      await page
        .getByRole("switch", {
          name: "Разрешить истёкший ответ при временном сбое DNS",
        })
        .press("Space");
      const grace = page.getByRole("spinbutton", {
        name: "Окно выдачи после TTL, с",
      });
      await grace.fill("30");
      await grace.press("Tab");
      const acknowledged = page.waitForResponse(
        (r) =>
          new URL(r.url()).pathname === "/api/dns/policy" &&
          r.request().method() === "PUT",
      );
      await page.getByRole("button", { name: "Сохранить настройки" }).click();
      assert.equal((await acknowledged).status(), 200);
      await page.reload();
      assert.equal(await retention.inputValue(), "120");
      assert.equal(await grace.inputValue(), "30");
      const second = await browser.newPage();
      second.setDefaultTimeout(6000);
      await second.goto(new URL("/#/dns", url).href);
      await second
        .getByRole("textbox", { name: "Домен для ручного прогрева" })
        .waitFor();
      await manual.getByRole("textbox").fill("Warm.Example.");
      await manual
        .getByRole("button", { name: "Добавить домен", exact: true })
        .click();
      await manual.getByText("warm.example", { exact: true }).waitFor();
      await second
        .getByRole("textbox", { name: "Домен для ручного прогрева" })
        .fill("concurrent.example");
      await second
        .getByRole("button", { name: "Добавить домен", exact: true })
        .click();
      await second.getByText(/Настройки изменились/).waitFor();
      await second
        .getByRole("button", { name: "Перечитать настройки со шлюза" })
        .click();
      await second.getByText("warm.example", { exact: true }).waitFor();
      await excluded.getByRole("textbox").fill("warm.example");
      await excluded
        .getByRole("button", { name: "Добавить исключение" })
        .click();
      await manual.getByText("Исключён из автопрогрева").waitFor();
      await page.reload();
      await excluded.getByText("warm.example", { exact: true }).waitFor();
      await manual.getByText("warm.example", { exact: true }).waitFor();
      await excluded
        .getByRole("button", { name: "Изменить исключение: warm.example" })
        .click();
      await excluded.getByRole("textbox").fill("new.example");
      await excluded
        .getByRole("button", { name: "Сохранить исключение" })
        .click();
      await excluded.getByText("new.example", { exact: true }).waitFor();
      await page.reload();
      await manual.getByText("warm.example", { exact: true }).waitFor();
      await excluded
        .getByRole("button", { name: "Снять исключение: new.example" })
        .click();
      await excluded
        .getByText("new.example", { exact: true })
        .waitFor({ state: "hidden" });
      const response = await page.request.get(
        new URL("/api/dns/policy", url).href,
      );
      assert.equal(response.status(), 200);
      const saved = await response.json();
      assert.deepEqual(saved.policy.exclusions, []);
      assert.deepEqual(saved.policy.manual, ["warm.example"]);
      await manual
        .getByRole("button", {
          name: "Удалить из ручного списка: warm.example",
        })
        .click();
      await manual.getByText("Домены вручную ещё не добавлены.").waitFor();
      await page.reload();
      await manual.getByText("Домены вручную ещё не добавлены.").waitFor();
    } finally {
      await browser.close();
    }
  },
);
