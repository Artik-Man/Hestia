import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

/** perform waits for the response caused by a UI action and reports only its HTTP status. */
export async function perform(page, method, path, action) {
  const [response] = await Promise.all([
    page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === path &&
        response.request().method() === method,
      { timeout: 120000 },
    ),
    action(),
  ]);
  assert.ok(response.ok(), `${method} ${path}: HTTP ${response.status()}`);
  return response;
}

/** openNew uses only the keyboard and requires one WireGuard menu item and one modal dialog. */
export async function openNew(page) {
  const add = page.getByRole("button", { name: "Добавить", exact: true });
  await add.focus();
  await page.keyboard.press("Enter");
  const menu = page.getByRole("menu");
  const item = menu.getByRole("menuitem", { name: "WireGuard", exact: true });
  await item.waitFor();
  assert.equal(await menu.getByRole("menuitem").count(), 1);
  await page.waitForFunction(() =>
    document.activeElement?.closest('[role="menu"]'),
  );
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog", {
    name: "Новое подключение WireGuard",
  });
  await dialog.waitFor();
  assert.equal(await page.getByRole("dialog").count(), 1);
  assert.ok(
    await dialog.evaluate((element) => element.matches(":modal")),
    "editor must be modal",
  );
  return dialog;
}

/** savedRow limits profile actions to the named connector, across the three connection tables. */
export function savedRow(page, name) {
  return page
    .getByRole("table")
    .getByRole("row")
    .filter({ has: page.getByRole("rowheader", { name, exact: true }) });
}

/** assign fills the public identity and initial group without accessing any secret. */
export async function assign(dialog, name, group) {
  await dialog.getByLabel("Название подключения", { exact: true }).fill(name);
  const select = dialog.getByRole("combobox");
  if (await select.evaluate((element) => element.tagName === "SELECT"))
    await select.selectOption(group.id);
  else {
    await select.click();
    await dialog
      .page()
      .getByRole("option", { name: group.name ?? group.id, exact: true })
      .click();
  }
  assert.equal(await dialog.locator("#profile-priority").count(), 0);
}

/** edit opens the stored profile through the row action and requires an explicit detail request. */
export async function edit(page, id, name) {
  await perform(page, "GET", "/api/awg/" + id, () =>
    savedRow(page, name)
      .getByRole("button", { name: "Редактировать профиль " + name })
      .click(),
  );
  const dialog = page.getByRole("dialog");
  await dialog.waitFor();
  assert.equal(await page.getByRole("dialog").count(), 1);
  await dialog.locator("#wg-PrivateKey").waitFor();
  const field = dialog.getByLabel("Название подключения", { exact: true });
  assert.ok(await field.isEditable());
  assert.equal(await field.inputValue(), name);
  return dialog;
}

/** exercise imports one profile, reopens it after a reload and deletes only its unique test ID. */
export async function exercise(page, url, file, afterImport) {
  page.setDefaultTimeout(15000);
  const name = "Тест WireGuard " + randomUUID();
  let id;
  const snapshot = await perform(page, "GET", "/api/groups-and-rules", () =>
    page.goto(url),
  );
  const { groups } = await snapshot.json();
  const group =
    groups.find((item) => item.id === process.env.HESTIA_E2E_GROUP) ??
    (!process.env.HESTIA_E2E_GROUP && groups[0]);
  assert.ok(group, "Test requires an existing group");
  const dialog = await openNew(page);
  await assign(dialog, name, group);
  const chooser = page.waitForEvent("filechooser");
  await dialog
    .getByRole("button", { name: "Импортировать .conf", exact: true })
    .press("Enter");
  await (await chooser).setFiles(file);
  await page.waitForFunction(() =>
    Boolean(document.querySelector("dialog #wg-PrivateKey")?.value),
  );
  if (afterImport) await afterImport(dialog);
  let saveRequested = false;
  let conflict = false;
  const saveURL = new URL("/api/awg", url).href;
  const trackRequest = (request) => {
    if (request.method() === "POST" && request.url() === saveURL)
      saveRequested = true;
  };
  const trackResponse = (response) => {
    if (
      response.request().method() === "POST" &&
      response.url() === saveURL &&
      response.status() === 409
    )
      conflict = true;
  };
  page.on("request", trackRequest);
  page.on("response", trackResponse);
  try {
    const created = await perform(page, "POST", "/api/awg", () =>
      dialog
        .getByRole("button", { name: "Сохранить", exact: true })
        .press("Enter"),
    );
    id = (await created.json()).id;
    assert.match(id, /^[0-9a-f-]{36}$/);
    await dialog.waitFor({ state: "hidden" });
    const row = savedRow(page, name);
    await row.waitFor();
    await page.goto("about:blank");
    await perform(page, "GET", "/api/awg", () => page.goto(url));
    await row.waitFor();
    const existing = await edit(page, id, name);
    assert.ok(
      await existing.locator("#wg-PrivateKey").inputValue(),
      "saved private key missing",
    );
    await existing.getByRole("button", { name: "Отмена", exact: true }).click();
    page.once("dialog", async (prompt) => {
      if (prompt.type() === "confirm" && prompt.message().includes(name))
        await prompt.accept();
      else await prompt.dismiss();
    });
    await perform(page, "DELETE", "/api/awg/" + id, () =>
      row.getByRole("button", { name: /Удалить/ }).press("Enter"),
    );
    await row.waitFor({ state: "detached" });
    await page.goto("about:blank");
    const list = await perform(page, "GET", "/api/awg", () => page.goto(url));
    assert.ok(!(await list.json()).some((record) => record.id === id));
  } catch (error) {
    if (saveRequested && !conflict) {
      await page.goto(url);
      // A lost create response leaves only this run's randomly tagged name to locate its record.
      if (!id) {
        const records = await page.evaluate(async () => {
          const response = await fetch("/api/awg", { redirect: "error" });
          if (!response.ok) throw new Error("Cannot inspect test profiles");
          return response.json();
        });
        const matches = records.filter((item) => item.name === name);
        assert.ok(
          matches.length <= 1,
          "Cleanup requires an unambiguous test profile",
        );
        id = matches[0]?.id;
      }
      if (!id) throw error;
      assert.match(
        id,
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      const status = await page.evaluate(
        async (path) =>
          (
            await fetch(path, {
              method: "DELETE",
              redirect: "error",
              signal: AbortSignal.timeout(120000),
            })
          ).status,
        "/api/awg/" + id,
      );
      if (status !== 404 && (status < 200 || status >= 300))
        throw new Error(`Cleanup failed for ${id}: HTTP ${status}`, {
          cause: error,
        });
    }
    throw error;
  } finally {
    page.off("request", trackRequest);
    page.off("response", trackResponse);
  }
}
