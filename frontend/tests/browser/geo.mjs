import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

/** Verifies keyboard access, one choice per country and persistent assignments across inventory changes. */
test("country matrix keeps explicit choices when the default changes", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(5000);
    const groups = [
      { id: "alpha", name: "Альфа", isDefault: true, exits: [] },
      { id: "beta", name: "Бета", isDefault: false, exits: [] },
    ];
    const unexpected = [];
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (route.request().method() !== "GET") {
        unexpected.push(path);
        return route.abort();
      }
      if (path === "/api/groups-and-rules")
        return route.fulfill({ json: { groups, lists: [] } });
      if (path === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (path === "/api/awg-underlays") return route.fulfill({ json: [] });
      if (path.startsWith("/api/")) {
        unexpected.push(path);
        return route.abort();
      }
      return route.fulfill({
        path: fileURLToPath(
          new URL(
            "../../dist/hestia/browser/" + (path.slice(1) || "index.html"),
            import.meta.url,
          ),
        ),
      });
    });
    await page.goto("http://127.0.0.1/#/country-map");
    const table = page.getByRole("table");
    const rows = table.locator("tbody tr");
    await rows.first().waitFor();
    assert.equal(await rows.count(), 249);
    const enabled = page.getByRole("switch");
    assert.equal(await enabled.isChecked(), false);
    assert.equal(
      await rows.locator("td:nth-child(2) input:checked").count(),
      249,
    );
    const bulk = table.getByRole("button", {
      name: /Назначить группу „.+“ всем странам/,
    });
    assert.equal(await bulk.count(), 2);
    await enabled.focus();
    await page.keyboard.press("Space");
    assert.equal(await enabled.isChecked(), true);
    await page.keyboard.press("Tab");
    if (
      await page
        .getByRole("region", { name: "Назначения стран" })
        .evaluate((el) => el === document.activeElement)
    )
      await page.keyboard.press("Tab");
    assert.equal(
      await bulk.first().evaluate((el) => el === document.activeElement),
      true,
    );
    await page.keyboard.press("Tab");
    assert.equal(
      await bulk.nth(1).evaluate((el) => el === document.activeElement),
      true,
    );
    await page.keyboard.press("Enter");
    await rows.first().locator("td:nth-child(3) input:checked").waitFor();
    assert.equal(
      await rows.locator("td:nth-child(3) input:checked").count(),
      249,
    );
    await page.keyboard.press("Tab");
    const first = rows.first().getByRole("radio");
    assert.equal(
      await first.nth(1).evaluate((el) => el === document.activeElement),
      true,
    );
    await page.keyboard.press("ArrowLeft");
    assert.equal(await first.first().isChecked(), true);
    await page.keyboard.press("Space");
    assert.equal(await first.first().isChecked(), true);
    groups[0].isDefault = false;
    groups[1].isDefault = true;
    groups.push({ id: "gamma", name: "Гамма", isDefault: false, exits: [] });
    await page.reload();
    await table.getByRole("columnheader", { name: /Гамма/ }).waitFor();
    assert.equal(await bulk.count(), 3);
    assert.equal(await enabled.isChecked(), true);
    assert.equal(await first.first().isChecked(), true);
    assert.equal(
      await rows.locator("td:nth-child(3) input:checked").count(),
      248,
    );
    await enabled.press("Space");
    await page.reload();
    await rows.first().waitFor();
    assert.equal(await enabled.isChecked(), false);
    assert.equal(await rows.locator("input:checked").count(), 249);
    assert.equal(await first.first().isChecked(), true);
    groups.shift();
    await page.reload();
    const missing = table.getByRole("columnheader", {
      name: /alpha.*Группа удалена/,
    });
    await missing.waitFor();
    assert.equal(
      await rows.first().locator("input:checked:disabled").count(),
      1,
    );
    await first.first().press("Space");
    await missing.waitFor({ state: "detached" });
    assert.equal(await rows.locator("input:checked").count(), 249);
    assert.equal(await enabled.isChecked(), false);
    assert.deepEqual(unexpected, []);
  } finally {
    await browser.close();
  }
});
