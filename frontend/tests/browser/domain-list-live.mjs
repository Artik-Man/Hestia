import assert from "node:assert/strict";
import test from "node:test";
import { chromium } from "playwright";

test("gateway creates, edits and deletes a domain list through its row actions", async (t) => {
  assert.ok(
    process.env.HESTIA_E2E_URL,
    "Set HESTIA_E2E_URL to the authorized gateway",
  );
  const url = new URL("/#/domain-lists", process.env.HESTIA_E2E_URL);
  const name = `E2E ${new Date().toISOString()}`;
  const masks = ["*.e2e.invalid"];
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    await page.goto(url.href);
    await page.getByRole("button", { name: "Создать список" }).click();
    const editor = page.getByRole("dialog", { name: "Новый список" });
    await editor.getByLabel("Название списка").fill(name);
    await editor.getByLabel("Маски, по одной в строке").fill(masks[0]);
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
    const snapshot = await page.request.get(
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
    const after = await page.request.get(
      new URL("/api/groups-and-rules", url).href,
    );
    assert.equal(after.status(), 200);
    assert.ok(!(await after.json()).lists.some((item) => item.id === saved.id));
    t.diagnostic(
      `Created, edited, cancelled deletion and deleted ${saved.id}. POST 201, PUT 200, DELETE 204; checked after reload.`,
    );
  } finally {
    await browser.close();
  }
});
