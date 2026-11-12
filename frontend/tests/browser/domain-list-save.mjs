import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { chromium } from "playwright";

test("domain lists persist after reload and compare edits against their original snapshot", async () => {
  const groups = [{ id: "main", isDefault: true, exits: [] }];
  const lists = [];
  const writes = [];
  let rejectEdit = true;
  let malformedConfirmation = false;
  const deletes = [];
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(4000);
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/hysteria2") return route.fulfill({ json: [] });
      if (path === "/api/awg-underlays") return route.fulfill({ json: [] });
      if (path === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (path === "/api/groups-and-rules")
        return route.fulfill({ json: { groups, lists } });
      if (path === "/api/domain-lists" && route.request().method() === "POST") {
        const payload = route.request().postDataJSON();
        writes.push(payload);
        const list = { ...payload, id: "list-1", enabled: false };
        lists.push(list);
        return route.fulfill({ status: 201, json: list });
      }
      if (
        path === "/api/domain-lists/list-1" &&
        route.request().method() === "PUT"
      ) {
        const payload = route.request().postDataJSON();
        writes.push(payload);
        if (rejectEdit) {
          rejectEdit = false;
          return route.fulfill({ status: 409, json: { detail: "conflict" } });
        }
        lists[0] = { ...lists[0], ...payload.list };
        return route.fulfill({
          status: 200,
          json: malformedConfirmation ? { id: lists[0].id } : lists[0],
        });
      }
      if (
        path === "/api/domain-lists/list-1" &&
        route.request().method() === "DELETE"
      ) {
        deletes.push(route.request().postDataJSON());
        if (deletes.length === 1)
          return route.fulfill({ status: 409, json: { detail: "conflict" } });
        lists.splice(0, 1);
        return route.fulfill({ status: 204 });
      }
      if (!/^\/(?:[\w.-]+)?$/.test(path)) return route.abort();
      const asset = new URL(
        "../../dist/hestia/browser/" + (path.slice(1) || "index.html"),
        import.meta.url,
      );
      return route.fulfill({ path: fileURLToPath(asset) });
    });
    await page.goto("http://127.0.0.1/#/domain-lists");
    await page.getByRole("button", { name: "Создать список" }).click();
    const dialog = page.getByRole("dialog");
    const name = dialog.getByLabel("Название списка");
    const masks = dialog.getByLabel("Маски, по одной в строке");
    const save = dialog.getByRole("button", { name: "Сохранить", exact: true });
    await name.fill("Примеры");
    await masks.fill("*.K.example.org");
    assert.equal(await save.isDisabled(), true);
    await masks.fill("*.example.org");
    await save.click();
    await page.getByRole("button", { name: "Примеры", exact: true }).waitFor();
    assert.deepEqual(writes[0], {
      name: "Примеры",
      group: "",
      masks: ["*.example.org"],
    });
    await page.reload();
    await page
      .getByRole("button", {
        name: "Редактировать список Примеры",
        exact: true,
      })
      .click();
    await name.fill("Новые примеры");
    await save.click();
    await dialog
      .locator("p-toast")
      .getByText(/Конфликт сохранения/)
      .waitFor();
    const closeNotice = dialog
      .locator("p-toast")
      .getByRole("button", { name: "Закрыть" });
    const controls = await dialog
      .locator("button, input, textarea, [tabindex]")
      .count();
    const initialFocus = await page.evaluateHandle(
      () => document.activeElement,
    );
    let closeNoticeFocused = false;
    for (let step = 0; step < controls * 2; step++) {
      await page.keyboard.press("Tab");
      if (await closeNotice.evaluate((button) => button.matches(":focus"))) {
        closeNoticeFocused = true;
        break;
      }
      if (
        await page.evaluate(
          (start) => document.activeElement === start,
          initialFocus,
        )
      ) {
        break;
      }
    }
    assert.ok(
      closeNoticeFocused,
      "Toast close button must be reachable by keyboard inside the editor dialog",
    );
    await page.keyboard.press("Enter");
    await closeNotice.waitFor({ state: "hidden" });
    assert.equal(await name.inputValue(), "Новые примеры");
    assert.deepEqual(writes[1], {
      expected: {
        id: "list-1",
        name: "Примеры",
        group: "",
        masks: ["*.example.org"],
        enabled: false,
      },
      list: { name: "Новые примеры", group: "", masks: ["*.example.org"] },
    });
    await dialog.getByRole("button", { name: "Обновить списки" }).click();
    await page
      .getByRole("button", {
        name: "Редактировать список Примеры",
        exact: true,
      })
      .click();
    await name.fill("Новые примеры");
    await save.click();
    await page
      .getByRole("button", { name: "Новые примеры", exact: true })
      .waitFor();
    await page.reload();
    await page
      .getByRole("button", { name: "Новые примеры", exact: true })
      .waitFor();
    assert.equal(lists.length, 1);
    assert.equal(writes.length, 3);
    await page.goto("http://127.0.0.1/#/domain-lists?list=list-1");
    await page
      .getByRole("heading", { name: "Доменный список Новые примеры" })
      .waitFor();
    await page.getByRole("button", { name: "Редактировать список" }).click();
    malformedConfirmation = true;
    await name.fill("После проверки");
    await save.click();
    await dialog
      .locator("p-toast")
      .getByRole("alert")
      .filter({ hasText: "Шлюз не подтвердил сохранение." })
      .waitFor();
    assert.equal(await save.isDisabled(), true);
    await dialog.getByRole("button", { name: "Отмена" }).click();
    await page
      .getByRole("heading", { name: "Доменный список После проверки" })
      .waitFor();
    await page.goto("http://127.0.0.1/#/domain-lists");
    const remove = page.getByRole("button", {
      name: "Удалить список После проверки",
      exact: true,
    });
    const confirm = page.getByRole("dialog", {
      name: "Удалить список",
      exact: true,
    });
    await remove.click();
    await confirm.getByText(/После проверки/).waitFor();
    await confirm.getByRole("button", { name: "Отмена" }).click();
    assert.equal(deletes.length, 0);
    await remove.click();
    await confirm.getByRole("button", { name: "Удалить", exact: true }).click();
    await confirm
      .locator("p-toast")
      .getByText(/Список изменился или шлюз занят/)
      .waitFor();
    assert.deepEqual(deletes, [lists[0]]);
    assert.equal(
      await confirm
        .getByRole("button", { name: "Удалить", exact: true })
        .isDisabled(),
      true,
    );
    await confirm.getByRole("button", { name: "Обновить списки" }).click();
    await remove.click();
    await confirm.getByRole("button", { name: "Удалить", exact: true }).click();
    await page.getByText("Нет доменных списков").waitFor();
    assert.equal(
      await page
        .getByRole("heading", { name: "Доменные списки", level: 1 })
        .evaluate((el) => el === document.activeElement),
      true,
    );
    await page.reload();
    await page.getByText("Нет доменных списков").waitFor();
    assert.equal(deletes.length, 2);
  } finally {
    await browser.close();
  }
});
