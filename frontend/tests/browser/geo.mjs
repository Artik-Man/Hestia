import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { regionCodes } from "../../src/core/models/geo-policy.ts";

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
    let version = 1;
    let saved = {
      version: String(version),
      enabled: false,
      assignments: Object.fromEntries(
        regionCodes.map((code) => [code, "alpha"]),
      ),
    };
    const attempts = [];
    const unexpected = [];
    let rejectNext = 0;
    let invalidRead = true;
    let holdWrite;
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/country-map" && route.request().method() === "PUT") {
        const body = route.request().postDataJSON();
        attempts.push(body);
        if (holdWrite) await holdWrite;
        assert.deepEqual(Object.keys(body).sort(), [
          "assignments",
          "enabled",
          "version",
        ]);
        assert.equal(body.version, saved.version);
        assert.deepEqual(
          Object.keys(body.assignments).sort(),
          [...regionCodes].sort(),
        );
        if (rejectNext) {
          const status = rejectNext;
          rejectNext = 0;
          if (status === 409)
            saved = {
              ...saved,
              version: String(++version),
              assignments: { ...saved.assignments, DE: "gamma" },
            };
          return route.fulfill({
            status,
            json: { status, detail: "write failed" },
          });
        }
        saved = { ...body, version: String(++version) };
        return route.fulfill({ json: saved });
      }
      if (route.request().method() !== "GET") {
        unexpected.push(path);
        return route.abort();
      }
      if (path === "/api/country-map") {
        if (invalidRead) {
          invalidRead = false;
          return route.fulfill({ json: { ...saved, assignments: {} } });
        }
        return route.fulfill({ json: saved });
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
    await page.addInitScript(
      ({ assignments }) =>
        localStorage.setItem(
          "hestia.country-map.draft.v1",
          JSON.stringify({ enabled: true, assignments }),
        ),
      saved,
    );
    await page.goto("http://127.0.0.1/#/country-map");
    await page.getByRole("alert").first().waitFor();
    assert.equal(await page.getByRole("switch").count(), 0);
    await page
      .getByRole("button", { name: "Повторить загрузку" })
      .press("Enter");
    const table = page.getByRole("table");
    const rows = table.locator("tbody tr");
    await rows.first().waitFor();
    assert.equal(await rows.count(), 249);
    const save = page.getByRole("button", { name: "Сохранить", exact: true });
    await save.waitFor();
    assert.equal(await save.count(), 1);
    assert.equal(await save.isDisabled(), true);
    const enabled = page.getByRole("switch");
    const bulk = table.getByRole("button", {
      name: /Назначить группу „.+“ всем странам/,
    });
    const first = rows.first().getByRole("radio");
    assert.equal(await enabled.isChecked(), false);
    assert.equal(
      await rows.locator("td:nth-child(2) input:checked").count(),
      249,
    );
    /** Measures the document coordinate so keyboard scrolling is independent of layout changes. */
    const tableTop = () =>
      table.evaluate((el) => el.getBoundingClientRect().top + window.scrollY);
    const originalTop = await tableTop();
    assert.ok(
      (await save.evaluate(
        (el) => el.getBoundingClientRect().bottom + window.scrollY,
      )) <= originalTop,
    );
    await bulk.nth(1).hover();
    await page.getByRole("tooltip").first().waitFor();
    assert.equal(await tableTop(), originalTop);
    await enabled.press("Space");
    await bulk.nth(1).press("Enter");
    await rows.first().locator("td:nth-child(3) input:checked").waitFor();
    assert.equal(
      await rows.locator("td:nth-child(3) input:checked").count(),
      249,
    );
    await first.nth(1).press("ArrowLeft");
    await first.first().press("Space");
    assert.equal(await first.first().isChecked(), true);
    assert.equal(await enabled.isChecked(), true);
    assert.equal(await save.isEnabled(), true);
    assert.equal(await tableTop(), originalTop);
    assert.equal(attempts.length, 0);

    /** Waits for the next explicit save response and checks its HTTP result. */
    const saveResponse = (status) =>
      page.waitForResponse(
        (response) =>
          response.url().endsWith("/api/country-map") &&
          response.request().method() === "PUT" &&
          response.status() === status,
      );
    const gate = Promise.withResolvers();
    holdWrite = gate.promise;
    const pending = page.waitForRequest(
      (request) =>
        request.url().endsWith("/api/country-map") &&
        request.method() === "PUT",
    );
    const success = saveResponse(200);
    await save.press("Enter");
    await pending;
    try {
      assert.equal(await save.isDisabled(), true);
      assert.equal(await tableTop(), originalTop);
    } finally {
      gate.resolve();
    }
    await success;
    holdWrite = undefined;
    await page.waitForFunction(
      () => document.querySelector("#country-routing")?.disabled === false,
    );
    assert.equal(await save.isDisabled(), true);
    assert.equal(await tableTop(), originalTop);
    assert.equal(attempts.length, 1);
    assert.equal(saved.enabled, true);
    assert.equal(
      Object.values(saved.assignments).filter((group) => group === "beta")
        .length,
      248,
    );

    groups[0].isDefault = false;
    groups[1].isDefault = true;
    groups.push({ id: "gamma", name: "Гамма", isDefault: false, exits: [] });
    await page.reload();
    await table.getByRole("columnheader", { name: /Гамма/ }).waitFor();
    assert.equal(await first.first().isChecked(), true);
    assert.equal(
      await rows.locator("td:nth-child(3) input:checked").count(),
      248,
    );
    await enabled.press("Space");
    assert.equal(attempts.length, 1);

    for (const status of [503, 409]) {
      rejectNext = status;
      const response = saveResponse(status);
      await save.press("Enter");
      await response;
      await page.getByRole("alert").first().waitFor();
      assert.equal(await enabled.isChecked(), false);
      assert.equal(saved.enabled, true);
    }
    await table
      .getByRole("row", { name: /Германия/ })
      .getByRole("radio", { name: /Гамма/, checked: true })
      .waitFor();
    assert.equal(attempts.length, 3);
    const retried = saveResponse(200);
    await save.press("Enter");
    await retried;
    assert.equal(saved.enabled, false);
    assert.equal(saved.assignments.DE, "gamma");
    assert.equal(attempts.length, 4);
    assert.deepEqual(unexpected, []);
  } finally {
    await browser.close();
  }
});
