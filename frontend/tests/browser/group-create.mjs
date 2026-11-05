import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { chromium } from "playwright";

test("groups preserve names, show modal and page Toasts, and require confirmation before deletion", async () => {
  const groups = [{ id: "main", isDefault: true, exits: [] }];
  const lists = [
    { id: "example-list", group: "", enabled: true, masks: ["example.test"] },
  ];
  let deleteCalls = 0;
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(4000);
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/awg-underlays") return route.fulfill({ json: [] });
      if (path === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (path === "/api/groups-and-rules")
        return route.fulfill({ json: { groups, lists } });
      if (path === "/api/groups" && route.request().method() === "POST") {
        assert.deepEqual(route.request().postDataJSON(), {
          name: "Запасной выход",
        });
        groups.push({
          id: "backup",
          name: "Запасной выход",
          isDefault: false,
          exits: [],
        });
        return route.fulfill({
          status: 201,
          json: { id: "backup", name: "Запасной выход" },
        });
      }
      if (path === "/api/groups/backup" && route.request().method() === "PUT") {
        if (route.request().postDataJSON().name === "Занято на шлюзе")
          return route.fulfill({ status: 409, json: { detail: "conflict" } });
        assert.deepEqual(route.request().postDataJSON(), {
          name: "Рабочая сеть",
        });
        groups[1].name = "Рабочая сеть";
        lists[0].group = "backup";
        return route.fulfill({
          status: 200,
          json: { id: "backup", name: "Рабочая сеть" },
        });
      }
      if (
        path === "/api/groups/backup" &&
        route.request().method() === "DELETE"
      ) {
        deleteCalls++;
        if (deleteCalls === 1)
          return route.fulfill({ status: 409, json: { detail: "busy" } });
        groups.splice(1, 1);
        lists[0].group = "";
        return route.fulfill({ status: 204 });
      }
      if (!/^\/(?:[\w.-]+)?$/.test(path)) return route.abort();
      const asset = new URL(
        "../../dist/hestia/browser/" + (path.slice(1) || "index.html"),
        import.meta.url,
      );
      return route.fulfill({ path: fileURLToPath(asset) });
    });
    await page.goto("http://127.0.0.1/#/groups?group=main");
    const groupHeading = page.getByRole("heading", {
      name: "main",
      exact: true,
    });
    await groupHeading.waitFor();
    assert.equal(await groupHeading.getByRole("link").count(), 0);
    const create = page.getByRole("button", {
      name: "Создать группу",
      exact: true,
    });
    await create.click();
    const dialog = page.getByRole("dialog");
    const name = dialog.getByLabel("Название группы");
    assert.equal(await name.inputValue(), "");
    await name.fill("Запасной выход");
    await name.press("Enter");
    await page
      .getByRole("list", { name: "Выходы группы Запасной выход" })
      .waitFor();
    await page
      .getByRole("alert")
      .getByText("Группа «Запасной выход» создана.")
      .waitFor();
    assert.equal(
      await page.getByRole("button", { name: "Удалить группу main" }).count(),
      0,
    );
    const edit = page.getByRole("button", {
      name: "Редактировать группу Запасной выход",
    });
    await edit.click();
    assert.equal(await name.inputValue(), "Запасной выход");
    await name.fill("ignored");
    await name.press("Escape");
    await dialog.waitFor({ state: "hidden" });
    assert.equal(
      await edit.evaluate((button) => button === document.activeElement),
      true,
    );
    await edit.click();
    assert.equal(await name.inputValue(), "Запасной выход");
    await name.fill("main");
    await dialog.getByRole("button", { name: "Сохранить" }).click();
    await dialog
      .getByText("Группа с таким названием уже существует.")
      .waitFor();
    await name.fill("Занято на шлюзе");
    await dialog.getByRole("button", { name: "Сохранить" }).click();
    const conflict = page
      .locator("p-toast [role=alert]")
      .filter({ hasText: "Название уже занято" });
    await conflict.waitFor();
    assert.equal(await name.inputValue(), "Занято на шлюзе");
    const onTop = await conflict.evaluate((el) => {
      const rect = el.getBoundingClientRect();
      return el.contains(
        document.elementFromPoint(
          rect.left + rect.width / 2,
          rect.top + rect.height / 2,
        ),
      );
    });
    assert.equal(
      onTop,
      true,
      "Toast must be visible and reachable over the native modal",
    );
    await conflict.getByRole("button", { name: "Закрыть" }).click();
    await name.fill("Рабочая сеть");
    await dialog.getByRole("button", { name: "Сохранить" }).click();
    const list = page.getByRole("list", { name: "Выходы группы Рабочая сеть" });
    await page
      .getByRole("alert")
      .getByText("Название группы изменено на «Рабочая сеть».")
      .waitFor();
    await list.getByText("Нет настроенных выходов").waitFor();
    await page.reload();
    await list.waitFor();
    assert.deepEqual(await page.locator(".order-group h3").allTextContents(), [
      "main",
      "Рабочая сеть",
    ]);
    await page
      .getByRole("button", { name: "Переместить группу Рабочая сеть" })
      .press("ArrowUp");
    await page
      .getByRole("button", { name: "Создать группу", disabled: true })
      .waitFor();
    await page.getByRole("button", { name: "Отменить изменения" }).click();
    const remove = page.getByRole("button", {
      name: "Удалить группу Рабочая сеть",
    });
    await remove.click();
    await dialog
      .getByText("Списки сохранятся без привязки: example-list.")
      .waitFor();
    await dialog.getByRole("button", { name: "Отмена" }).click();
    assert.equal(deleteCalls, 0);
    await remove.click();
    await dialog.getByRole("button", { name: "Удалить", exact: true }).click();
    await page
      .getByRole("alert")
      .getByText(/Шлюз занят или группа теперь используется/)
      .waitFor();
    await remove.click();
    await dialog.getByRole("button", { name: "Удалить", exact: true }).click();
    await page
      .getByRole("alert")
      .getByText("Группа «Рабочая сеть» удалена.")
      .waitFor();
    await list.waitFor({ state: "hidden" });
    assert.equal(deleteCalls, 2);
    await page.reload();
    await page.getByRole("list", { name: "Выходы группы main" }).waitFor();
    assert.equal(await list.count(), 0);
  } finally {
    await browser.close();
  }
});
