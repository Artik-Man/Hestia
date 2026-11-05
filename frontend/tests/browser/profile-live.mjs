import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { chromium } from "playwright";
import { exercise } from "./profile-flow.mjs";

test("gateway imports the supplied AWG file and deletes the persisted profile", async () => {
  if (!process.env.HESTIA_E2E_URL)
    throw new Error("Set HESTIA_E2E_URL to the authorized gateway origin");
  const url = new URL("/#/connections", process.env.HESTIA_E2E_URL);
  const file =
    process.env.HESTIA_E2E_CONFIG ??
    fileURLToPath(
      new URL("../../../private/hestia_amnezia_for_awg.conf", import.meta.url),
    );
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    const baseline = await page.request.get(new URL("/api/awg", url).href, {
      maxRedirects: 0,
      timeout: 15000,
    });
    assert.equal(
      baseline.status(),
      200,
      "Cannot verify the gateway's initial AWG profiles",
    );
    const profiles = await baseline.json();
    assert.ok(
      Array.isArray(profiles) && profiles.length === 0,
      "The live test requires an empty AWG profile list; existing profiles must be preserved",
    );
    await page.route("**/*", async (route) => {
      const request = route.request();
      if (new URL(request.url()).origin !== url.origin) return route.abort();
      if (
        !["POST", "PUT"].includes(request.method()) &&
        !/^\/api\/awg\/[^/]+$/.test(new URL(request.url()).pathname)
      )
        return route.continue();
      const response = await route.fetch({ maxRedirects: 0, timeout: 120000 });
      if (response.status() >= 300 && response.status() < 400)
        return route.abort();
      return route.fulfill({ response });
    });
    await exercise(page, url.href, file);
  } finally {
    await browser.close();
  }
});
