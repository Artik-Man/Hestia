import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";

const require = createRequire(
  resolve(process.env.HESTIA_VALIDATION_REPO, "frontend/package.json"),
);
const { chromium } = require("playwright");

test("gateway creates, edits and deletes a domain list through its row actions", async (t) => {
  assert.ok(
    process.env.HESTIA_E2E_URL,
    "Set HESTIA_E2E_URL to the authorized gateway",
  );
  const url = new URL("/#/domain-lists", process.env.HESTIA_E2E_URL);
  assert.equal(url.hostname, "127.0.0.1");
  assert.equal(url.protocol, "http:");
  const name = `Validation ${randomUUID()}`;
  const masks = ["*.e2e.invalid"];
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
    handleSIGTERM: false,
    handleSIGINT: false,
  });
  const context = await browser.newContext({ serviceWorkers: "block" });
  const page = await context.newPage();
  await page.route("**/*", (route) =>
    new URL(route.request().url()).origin === url.origin
      ? route.continue()
      : route.abort(),
  );
  let mayHaveCreated = false;
  let creationConfirmed = false;
  let completed = false;
  // interrupt closes UI actions so the finally block can restore only this run's list.
  const interrupt = () => {
    process.exitCode = 130;
    void page.close();
  };
  process.once("SIGTERM", interrupt);
  process.once("SIGINT", interrupt);
  try {
    const baseline = await context.request.get(
      new URL("/api/groups-and-rules", url).href,
      { maxRedirects: 0, timeout: 310000 },
    );
    assert.equal(baseline.status(), 200);
    const before = await baseline.json();
    assert.deepEqual(before.lists, []);
    assert.equal(before.groups.length, 1);
    assert.equal(before.groups[0].id, "default");
    assert.deepEqual(before.groups[0].exits, []);
    await page.goto(url.href);
    await page.getByRole("button", { name: "Создать список" }).click();
    const editor = page.getByRole("dialog", { name: "Новый список" });
    await editor.getByLabel("Название списка").fill(name);
    await editor.getByLabel("Маски, по одной в строке").fill(masks[0]);
    mayHaveCreated = true;
    const [response] = await Promise.all([
      page.waitForResponse(
        (r) =>
          r.url() === new URL("/api/domain-lists", url).href &&
          r.request().method() === "POST",
        { timeout: 310000 },
      ),
      editor.getByRole("button", { name: "Сохранить", exact: true }).click(),
    ]);
    assert.equal(response.status(), 201, await response.text());
    const saved = await response.json();
    creationConfirmed = true;
    assert.ok(typeof saved.id === "string" && saved.id.length > 0);
    assert.equal(saved.name, name);
    assert.equal(saved.group, "");
    assert.equal(saved.enabled, false);
    assert.deepEqual(saved.masks, masks);
    await page
      .getByRole("button", {
        name: `Редактировать список ${name}`,
        exact: true,
      })
      .waitFor();
    await page.reload();
    const row = page.getByRole("row").filter({
      has: page.getByRole("button", {
        name: `Редактировать список ${name}`,
        exact: true,
      }),
    });
    await row.getByText(masks[0], { exact: true }).waitFor();
    const snapshot = await context.request.get(
      new URL("/api/groups-and-rules", url).href,
    );
    assert.equal(snapshot.status(), 200);
    const matches = (await snapshot.json()).lists.filter(
      (item) => item.id === saved.id,
    );
    assert.equal(matches.length, 1);
    assert.deepEqual(matches[0].masks, masks);
    assert.equal(matches[0].name, name);
    assert.equal(matches[0].group, "");
    assert.equal(matches[0].enabled, false);
    const itemUrl = new URL(`/api/domain-lists/${saved.id}`, url).href;
    await row
      .getByRole("button", {
        name: `Редактировать список ${name}`,
        exact: true,
      })
      .click();
    const edit = page.getByRole("dialog", { name: "Изменить список" });
    const updatedName = name + " edited";
    await edit.getByLabel("Название списка").fill(updatedName);
    const [update] = await Promise.all([
      page.waitForResponse(
        (r) => r.url() === itemUrl && r.request().method() === "PUT",
      ),
      edit.getByRole("button", { name: "Сохранить", exact: true }).click(),
    ]);
    assert.equal(update.status(), 200, await update.text());
    assert.equal((await update.json()).id, saved.id);
    const remove = page.getByRole("button", {
      name: `Удалить список ${updatedName}`,
      exact: true,
    });
    await remove.click();
    const confirm = page.getByRole("dialog");
    await confirm.getByRole("button", { name: "Отмена", exact: true }).click();
    await page.reload();
    await remove.click();
    const [deleted] = await Promise.all([
      page.waitForResponse(
        (r) => r.url() === itemUrl && r.request().method() === "DELETE",
      ),
      confirm.getByRole("button", { name: "Удалить", exact: true }).click(),
    ]);
    assert.equal(deleted.status(), 204, await deleted.text());
    await remove.waitFor({ state: "hidden" });
    await page.reload();
    await page.getByRole("button", { name: "Создать список" }).waitFor();
    assert.equal(await remove.count(), 0);
    const after = await context.request.get(
      new URL("/api/groups-and-rules", url).href,
    );
    assert.equal(after.status(), 200);
    const restored = await after.json();
    assert.ok(!restored.lists.some((item) => item.id === saved.id));
    assert.deepEqual(restored, before);
    completed = true;
    t.diagnostic(
      `Created, edited, cancelled deletion and deleted ${saved.id}. POST 201, PUT 200, DELETE 204; checked after reload.`,
    );
  } finally {
    process.removeListener("SIGTERM", interrupt);
    process.removeListener("SIGINT", interrupt);
    process.on("SIGTERM", () => {});
    process.on("SIGINT", () => {});
    try {
      if (mayHaveCreated && !completed) {
        const deadline = Date.now() + (creationConfirmed ? 0 : 100000);
        while (true) {
          const response = await context.request.get(
            new URL("/api/groups-and-rules", url).href,
            { maxRedirects: 0, timeout: 310000 },
          );
          assert.equal(response.status(), 200);
          const current = await response.json();
          assert.ok(Array.isArray(current.lists));
          const owned = current.lists.filter(
            (item) => item.name === name || item.name === name + " edited",
          );
          assert.ok(owned.length <= 1, "ambiguous owned UI list");
          if (owned.length) {
            const item = owned[0];
            assert.deepEqual(item.masks, masks, "concurrent edit preserved");
            assert.equal(item.group, "", "concurrent binding preserved");
            assert.equal(item.enabled, false);
            const removed = await context.request.delete(
              new URL(`/api/domain-lists/${item.id}`, url).href,
              { data: item, timeout: 310000, maxRedirects: 0 },
            );
            assert.equal(
              removed.status(),
              204,
              "cleanup CAS failed; preserved",
            );
            break;
          }
          if (Date.now() >= deadline) break;
          await new Promise((resolveWait) => setTimeout(resolveWait, 250));
        }
      }
    } finally {
      await browser.close();
    }
  }
});
