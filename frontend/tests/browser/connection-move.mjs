import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { chromium } from "playwright";

test("dragging an exit into an empty group stages a cancellable change until Save", async () => {
  const id = "awg-home";
  let assigned = "source";
  let writes = 0;
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({
      viewport: { width: 1280, height: 960 },
    });
    page.setDefaultTimeout(4000);
    await page.route("**/*", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/awg-underlays")
        return route.fulfill({
          json: [{ id, type: "direct", name: "Мой интернет" }],
        });
      if (path === "/api/navigation")
        return route.fulfill({ json: { grafanaUrl: "" } });
      if (path === "/api/groups-and-rules")
        return route.fulfill({
          json: {
            groups: [
              { id: "source", name: "Основная" },
              { id: "target", name: "Резерв" },
            ].map((g, i) => ({
              ...g,
              isDefault: i === 0,
              exits: g.id === assigned ? [{ id, available: true }] : [],
            })),
            lists: [],
          },
        });
      if (path === "/api/group-order" && route.request().method() === "PUT") {
        const { expected, groups } = route.request().postDataJSON();
        assert.deepEqual(expected, [
          { id: "source", exits: [id] },
          { id: "target", exits: [] },
        ]);
        assert.deepEqual(groups, [
          { id: "source", exits: [] },
          { id: "target", exits: [id] },
        ]);
        writes++;
        assigned = "target";
        return route.fulfill({ status: 200, json: { groups } });
      }
      if (path.startsWith("/api/"))
        throw new Error(
          "Unexpected API operation " + route.request().method() + " " + path,
        );
      return route.fulfill({
        path: fileURLToPath(
          new URL(
            "../../dist/hestia/browser/" + (path.slice(1) || "index.html"),
            import.meta.url,
          ),
        ),
      });
    });
    await page.goto("http://127.0.0.1/#/groups");
    const handle = page.getByRole("button", {
      name: "Переместить выход Мой интернет",
    });
    const target = page.getByRole("list", { name: "Выходы группы Резерв" });
    const source = page.getByRole("list", { name: "Выходы группы Основная" });
    await target.getByText("Нет настроенных выходов").waitFor();
    const from = await handle.boundingBox();
    const to = await target.boundingBox();
    assert.ok(from && to);
    const x = from.x + from.width / 2,
      y = from.y + from.height / 2;
    await page.mouse.move(x, y);
    await page.mouse.down();
    await page.mouse.move(x, y + 12, { steps: 3 });
    await page.mouse.move(x, to.y + to.height / 2, { steps: 16 });
    await page.mouse.up();
    await target
      .getByRole("button", { name: "Переместить выход Мой интернет" })
      .waitFor();
    assert.equal(writes, 0);
    await page.getByRole("button", { name: "Отменить изменения" }).click();
    await source
      .getByRole("button", { name: "Переместить выход Мой интернет" })
      .waitFor();
    assert.equal(writes, 0);
    await handle.press("Alt+ArrowDown");
    await target
      .getByRole("button", { name: "Переместить выход Мой интернет" })
      .waitFor();
    assert.equal(writes, 0);
    await page.getByRole("button", { name: "Сохранить", exact: true }).click();
    await page.getByText("Порядок применён шлюзом.").waitFor();
    await page.reload();
    await target
      .getByRole("button", { name: "Переместить выход Мой интернет" })
      .waitFor();
    assert.equal(writes, 1);
  } finally {
    await browser.close();
  }
});
