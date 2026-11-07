import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { expect } from "playwright/test";
import {
  assign,
  edit,
  exercise,
  openNew,
  perform,
  savedRow,
} from "./profile-flow.mjs";

const origin = "http://127.0.0.1";
const wifiID = "00330000-1111-4222-8333-444455556666";
const url = origin + "/#/connections";
const storedID = "10330000-1111-4222-8333-444455556666";
const group = {
  id: "test",
  isDefault: true,
  exits: [{ id: storedID, available: true }],
};
const required = {
  Address: "10.66.0.2/32",
  DNS: "10.66.0.1",
  PrivateKey: Buffer.alloc(32, 1).toString("base64"),
  PublicKey: Buffer.alloc(32, 2).toString("base64"),
  Endpoint: "192.0.2.1:51820",
  AllowedIPs: "0.0.0.0/0",
};
const optional = {
  HeaderProtectionKey: Buffer.alloc(32, 3).toString("base64"),
  PresharedKey: Buffer.alloc(32, 4).toString("base64"),
};
const config = `[Interface]
Address = ${required.Address}
DNS = ${required.DNS}
PrivateKey = ${required.PrivateKey}
HeaderProtectionKey = ${optional.HeaderProtectionKey}
S1 = 12
S2 = 13
S3 = 14
S4 = 15
[Peer]
PublicKey = ${required.PublicKey}
PresharedKey = ${optional.PresharedKey}
Endpoint = ${required.Endpoint}
AllowedIPs = ${required.AllowedIPs}
`;

/** fixture serves only a local production bundle and a synthetic typed API, retaining public and private records separately. */
async function fixture(
  page,
  { includeOrphan = false, hasRadio = true, directName } = {},
) {
  const publicRecord = {
    id: storedID,
    name: "existing",
    group: "test",
    priority: 2,
    status: "ready",
    ipv6Blocked: true,
  };
  const records = new Map([[publicRecord.id, publicRecord]]);
  const profiles = new Map([[publicRecord.id, config]]);
  if (includeOrphan) {
    records.set("pending", {
      ...publicRecord,
      id: "pending",
      name: "pending",
      status: "checking",
      priority: 3,
    });
    profiles.set("pending", config);
  }
  const direct = { id: "wan-a", type: "direct", name: directName };
  const physical = {
    interfaces: [
      {
        interfaceName: "eth0",
        kind: "ethernet",
        present: true,
        carrierState: "down",
        online: false,
        exitIds: ["wan-a"],
      },
      {
        interfaceName: "eth1",
        kind: "ethernet",
        present: false,
        carrierState: "unknown",
        online: false,
        exitIds: ["wan-b"],
      },
      {
        interfaceName: "wlan0",
        kind: "wifi",
        present: true,
        carrierState: "down",
        online: false,
        exitIds: [],
      },
      {
        interfaceName: "wlan1",
        kind: "wifi",
        present: true,
        carrierState: "down",
        online: false,
        exitIds: [],
      },
    ],
    wifiProfiles: [],
    wifiAvailable: true,
  };
  if (!hasRadio)
    physical.interfaces = physical.interfaces.filter(
      (item) => item.kind !== "wifi",
    );
  const state = { loseNext: false, rejectNext: false, writes: [], details: [] };
  await page.route("**/*", async (route) => {
    const req = route.request();
    const { pathname, origin: requestOrigin } = new URL(req.url());
    if (requestOrigin !== origin) return route.abort();
    if (pathname === "/api/hysteria2" && req.method() === "GET")
      return route.fulfill({ json: [] });
    if (pathname === "/api/physical-connections")
      return route.fulfill({ json: physical });
    const wifiPath = "/api/wifi-connections/" + wifiID;
    if (pathname === wifiPath && req.method() === "DELETE") {
      physical.wifiProfiles = [];
      return route.fulfill({ status: 204 });
    }
    if (
      (pathname === "/api/wifi-connections" && req.method() === "POST") ||
      (pathname === wifiPath && req.method() === "PUT")
    ) {
      const data = req.postDataJSON();
      state.writes.push({ method: req.method(), pathname, data });
      const { interfaceName, band, security, ssid } = data;
      physical.wifiProfiles = [
        {
          id: wifiID,
          interfaceName,
          band,
          security,
          ssid,
          active: true,
        },
      ];
      return route.fulfill({ status: 204 });
    }
    if (pathname === "/api/navigation")
      return route.fulfill({ json: { grafanaUrl: "" } });
    if (pathname === "/api/groups-and-rules")
      return route.fulfill({
        json: {
          groups: [
            {
              ...group,
              exits: [
                { id: "wan-a", available: false },
                ...[...records.keys()]
                  .filter((id) => id !== "pending")
                  .map((id) => ({ id, available: true })),
              ],
            },
          ],
          lists: [],
        },
      });
    if (pathname === "/api/awg-underlays")
      return route.fulfill({
        json: [
          direct,
          { id: "wan-b", type: "direct" },
          { id: "unmatched", type: "direct" },
          ...[...records.values()].map(({ id, name }) => ({
            name,
            id,
            type: id === storedID ? "amneziawg" : "wireguard",
          })),
        ],
      });
    if (pathname === "/api/connections/wan-a/name" && req.method() === "PUT") {
      const data = req.postDataJSON();
      state.writes.push({ method: req.method(), pathname, data });
      direct.name = data.name;
      return route.fulfill({ json: direct });
    }
    if (pathname === "/api/awg" && req.method() === "GET")
      return route.fulfill({ json: [...records.values()] });
    const id = pathname.split("/")[3];
    if (/^\/api\/awg\/[a-z0-9-]+$/.test(pathname) && req.method() === "GET") {
      state.details.push(id);
      if (!records.has(id)) return route.fulfill({ status: 404 });
      const { name, group, priority } = records.get(id);
      return route.fulfill({
        json: {
          id,
          name,
          group,
          priority,
          underlays: records.get(id).underlays ?? [],
          profile: profiles.get(id),
        },
        headers: { "Cache-Control": "no-store" },
      });
    }
    if (
      (pathname === "/api/awg" && req.method() === "POST") ||
      (profiles.has(id) && req.method() === "PUT")
    ) {
      const data = req.postDataJSON();
      state.writes.push({ method: req.method(), data });
      if (state.rejectNext) {
        state.rejectNext = false;
        return route.fulfill({
          status: 422,
          json: { detail: "invalid profile" },
        });
      }
      const tag = req.method() === "PUT" ? id : randomUUID();
      const record = {
        id: tag,
        name: data.name,
        group: records.get(tag)?.group ?? data.group,
        underlays: data.underlays,
        priority: records.get(tag)?.priority ?? records.size + 2,
        status: "ready",
        ipv6Blocked: true,
      };
      records.set(tag, record);
      profiles.set(tag, data.profile);
      if (state.loseNext) {
        state.loseNext = false;
        return route.fulfill({ status: 502 });
      }
      return route.fulfill({ json: record });
    }
    if (req.method() === "DELETE" && records.delete(id)) {
      profiles.delete(id);
      state.writes.push({ method: "DELETE", id });
      return route.fulfill({ status: 204 });
    }
    if (!/^\/(?:[\w.-]+)?$/.test(pathname)) return route.abort();
    const asset = new URL(
      "../../dist/hestia/browser/" + (pathname.slice(1) || "index.html"),
      import.meta.url,
    );
    return route.fulfill({ path: fileURLToPath(asset) });
  });
  return { records, profiles, state };
}

/** file wraps a synthetic .conf for browser file input without touching local VPN credentials. */
function file(content) {
  return {
    name: "synthetic.conf",
    mimeType: "text/plain",
    buffer: Buffer.from(content),
  };
}

test("the keyboard menu imports editable WireGuard fields and an ambiguous save cleans up only its own ID", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    const { records, state } = await fixture(page);
    await exercise(page, url, file(config), async (dialog) => {
      for (const [name, value] of Object.entries({ ...required, ...optional }))
        assert.equal(
          await dialog.locator("#wg-" + name).inputValue(),
          value,
          name,
        );
      await dialog.locator("#wg-Endpoint").fill("198.51.100.40:12345");
    });
    assert.match(
      state.writes[0].data.profile,
      /Endpoint\s*=\s*198\.51\.100\.40:12345/,
    );
    for (const value of Object.values(optional))
      assert.ok(state.writes[0].data.profile.includes(value));
    await page.goto("about:blank");
    state.loseNext = true;
    await assert.rejects(
      exercise(page, url, file(config)),
      /POST \/api\/awg: HTTP 502/,
    );
    assert.deepEqual([...records.keys()], [storedID]);
  } finally {
    await browser.close();
  }
});

test("one dialog creates manually, reopens all stored keys, retains drafts on failure, and confirms deletion", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    const { records, profiles, state } = await fixture(page);
    await perform(page, "GET", "/api/awg", () => page.goto(url));
    assert.equal(state.details.length, 0);
    await savedRow(page, "existing").waitFor();
    assert.equal(await page.getByRole("table").count(), 3);
    for (const name of ["Ethernet", "Wi-Fi", "Виртуальные подключения"])
      assert.ok(
        await page.getByRole("table", { name, exact: true }).isVisible(),
      );
    assert.equal(await savedRow(page, "existing").count(), 1);
    const native = savedRow(page, "wan-a");
    await native.waitFor();
    assert.equal(
      await native.getByText("Линк не поднят", { exact: true }).count(),
      1,
    );
    assert.deepEqual(
      await page
        .getByRole("table", { name: "Виртуальные подключения" })
        .getByRole("columnheader")
        .allTextContents(),
      [
        "Название подключения",
        "Тип подключения",
        "Доступность",
        "Подключается через",
        "Редактировать",
        "Удалить",
      ],
    );

    assert.equal(
      await native.getByRole("button", { name: /Удалить/ }).count(),
      0,
    );
    const add = page.getByRole("button", { name: "Добавить", exact: true });
    await page.setViewportSize({ width: 360, height: 640 });
    const fresh = await openNew(page);
    await fresh.locator("summary").press("Enter");
    assert.ok(await fresh.locator("#wg-HeaderProtectionKey").isVisible());
    assert.ok(
      await fresh.evaluate((node) => {
        const bounds = node.getBoundingClientRect();
        const footer = node
          .querySelector('button[type="submit"]')
          .getBoundingClientRect();
        return (
          node.scrollWidth <= node.clientWidth + 1 &&
          bounds.left >= 0 &&
          bounds.right <= innerWidth &&
          footer.left >= bounds.left &&
          footer.right <= bounds.right &&
          footer.top >= 0 &&
          footer.bottom <= innerHeight
        );
      }),
      "all dialog actions must fit a narrow viewport",
    );
    const wireguard = config
      .split("\n")
      .filter(
        (line) => !/^(HeaderProtectionKey|PresharedKey|S[1-4]) =/.test(line),
      )
      .join("\n");
    await fresh.locator("input[type=file]").setInputFiles(file(wireguard));
    await fresh
      .getByRole("status")
      .filter({ hasText: "synthetic.conf" })
      .waitFor();
    assert.equal(
      await fresh.locator("#wg-Endpoint").inputValue(),
      required.Endpoint,
    );
    assert.equal(await fresh.locator("#wg-PresharedKey").inputValue(), "");
    assert.equal(
      await fresh.locator("#wg-HeaderProtectionKey").inputValue(),
      "",
    );
    await fresh
      .getByRole("button", { name: "Отмена", exact: true })
      .press("Enter");
    await page.waitForFunction(
      (trigger) => document.activeElement === trigger,
      await add.elementHandle(),
    );
    assert.equal(state.writes.length, 0);
    const dialog = await openNew(page);
    await assign(dialog, "Офис № 2", group);
    for (const [name, value] of Object.entries(required))
      await dialog.locator("#wg-" + name).fill(value);
    await dialog
      .locator("input[type=file]")
      .setInputFiles(file(config + "PostUp = run-me\n"));
    await dialog.getByRole("alert").first().waitFor();
    assert.equal(
      await dialog.locator("#wg-Endpoint").inputValue(),
      required.Endpoint,
    );
    const save = dialog.getByRole("button", { name: "Сохранить", exact: true });
    await perform(page, "POST", "/api/awg", () => save.press("Enter"));
    await dialog.waitFor({ state: "detached" });
    assert.equal(records.size, 2);
    assert.equal(state.writes[0].data.group, "test");
    assert.ok(!Object.hasOwn(state.writes[0].data, "priority"));
    assert.ok(!Object.hasOwn(state.writes[0].data, "id"));
    const createdID = [...records.values()].find(
      (record) => record.name === "Офис № 2",
    ).id;
    assert.equal(records.get(createdID).priority, 3);
    assert.ok(!(await page.locator("body").innerText()).includes(createdID));
    assert.equal(
      await savedRow(page, "existing")
        .getByText("Доступно", { exact: true })
        .count(),
      1,
    );
    const existing = await edit(page, storedID, "existing");
    assert.equal(await existing.locator("#profile-priority").count(), 0);
    for (const [name, value] of Object.entries({ ...required, ...optional })) {
      const input = existing.locator("#wg-" + name);
      assert.equal(await input.inputValue(), value, name);
      assert.notEqual(await input.getAttribute("type"), "password", name);
    }
    await existing.locator("#wg-Endpoint").fill("203.0.113.2:443");
    await existing
      .getByRole("button", { name: "Отмена", exact: true })
      .press("Enter");
    await existing.waitFor({ state: "detached" });
    const trigger = savedRow(page, "existing").getByRole("button", {
      name: "Редактировать профиль existing",
    });
    await page.waitForFunction(
      () =>
        document.activeElement?.getAttribute("aria-label") ===
        "Редактировать профиль existing",
    );
    assert.ok(await trigger.isVisible());
    assert.equal(state.writes.length, 1);
    const current = await edit(page, storedID, "existing");
    assert.equal(
      await current.locator("#wg-Endpoint").inputValue(),
      required.Endpoint,
    );
    await current.locator("#wg-Endpoint").fill("203.0.113.3:443");
    await current
      .getByLabel("Название подключения", { exact: true })
      .fill("Рабочий VPN");
    state.rejectNext = true;
    const submit = current.getByRole("button", {
      name: "Сохранить",
      exact: true,
    });
    await assert.rejects(
      perform(page, "PUT", "/api/awg/" + storedID, () => submit.press("Enter")),
      /HTTP 422/,
    );
    await current.getByRole("alert").first().waitFor();
    assert.equal(
      await current.locator("#wg-Endpoint").inputValue(),
      "203.0.113.3:443",
    );
    assert.equal(profiles.get(storedID), config);
    await perform(page, "PUT", "/api/awg/" + storedID, () =>
      submit.press("Enter"),
    );
    await current.waitFor({ state: "detached" });
    for (const field of ["group", "priority"])
      assert.ok(!Object.hasOwn(state.writes.at(-1).data, field));
    assert.equal(records.get(storedID).group, "test");
    assert.equal(records.get(storedID).priority, 2);
    await savedRow(page, "Рабочий VPN").waitFor();
    assert.equal(records.get(storedID).name, "Рабочий VPN");
    const saved = profiles.get(storedID);
    assert.match(saved, /Endpoint\s*=\s*203\.0\.113\.3:443/);
    for (const value of [required.PrivateKey, ...Object.values(optional)])
      assert.ok(saved.includes(value));
    const remove = savedRow(page, "Офис № 2").getByRole("button", {
      name: /Удалить/,
    });
    assert.equal((await remove.innerText()).trim(), "");
    assert.ok(
      await remove.evaluate((button) => {
        const icon = button.querySelector("svg, i, span") ?? button;
        const [r, g, b] = getComputedStyle(icon)
          .color.match(/\d+/g)
          .map(Number);
        return r > g * 1.4 && r > b * 1.4;
      }),
      "delete icon must be red",
    );
    page.once("dialog", (prompt) => prompt.dismiss());
    await remove.press("Enter");
    assert.ok(records.has(createdID));
    page.once("dialog", (prompt) => prompt.accept());
    await perform(page, "DELETE", "/api/awg/" + createdID, () =>
      remove.press("Enter"),
    );
    assert.deepEqual([...records.keys()], [storedID]);
    assert.ok(await add.isVisible());
  } finally {
    await browser.close();
  }
});

test("ordered transports persist and the automatic mode clears all explicit choices", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    const { state } = await fixture(page);
    await perform(page, "GET", "/api/awg", () => page.goto(url));
    let dialog = await edit(page, storedID, "existing");
    const trigger = dialog.locator("#underlay-trigger");
    assert.match(await trigger.innerText(), /Любое интернет-подключение/);
    await trigger.click();
    assert.equal(
      await dialog
        .getByRole("checkbox", { name: "existing", exact: true })
        .count(),
      0,
    );
    await dialog.getByLabel("wan-a", { exact: true }).check();
    await dialog.getByLabel("wan-b", { exact: true }).check();
    const rows = dialog.locator(".transport-row");
    await rows
      .filter({ hasText: "wan-b" })
      .dragTo(rows.filter({ hasText: "wan-a" }));
    assert.match(await trigger.innerText(), /wan-b → wan-a/);
    await perform(page, "PUT", "/api/awg/" + storedID, () =>
      dialog.getByRole("button", { name: "Сохранить", exact: true }).click(),
    );
    await dialog.waitFor({ state: "detached" });
    assert.deepEqual(state.writes.at(-1).data.underlays, ["wan-b", "wan-a"]);
    dialog = await edit(page, storedID, "existing");
    assert.match(await trigger.innerText(), /wan-b → wan-a/);
    await trigger.click();
    await dialog
      .getByRole("checkbox", { name: "Любое интернет-подключение" })
      .check();
    await perform(page, "PUT", "/api/awg/" + storedID, () =>
      dialog.getByRole("button", { name: "Сохранить", exact: true }).click(),
    );
    assert.deepEqual(state.writes.at(-1).data.underlays, []);
  } finally {
    await browser.close();
  }
});

test("connections retain profiles absent from the snapshot and native exits absent from storage", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    await fixture(page, { includeOrphan: true });
    await perform(page, "GET", "/api/awg", () => page.goto(url));

    await savedRow(page, "wan-b")
      .getByText("Адаптер отсутствует", { exact: true })
      .waitFor();
    assert.equal(await savedRow(page, "unmatched").count(), 0);
    const pending = savedRow(page, "pending");
    await pending.getByText("Проверяется", { exact: true }).waitFor();
    assert.ok(
      await pending.getByRole("button", { name: /Редактировать/ }).isEnabled(),
    );
    await pending
      .getByRole("cell", { name: "WireGuard", exact: true })
      .waitFor();
    await savedRow(page, "existing")
      .getByRole("cell", { name: "AmneziaWG", exact: true })
      .waitFor();
    assert.equal(await savedRow(page, "wan-a").getByRole("button").count(), 1);
    assert.deepEqual(
      (
        await page
          .getByRole("table", { name: "Виртуальные подключения" })
          .getByRole("rowheader")
          .allTextContents()
      )
        .map((name) => name.trim())
        .sort(),
      ["existing", "pending"],
    );
  } finally {
    await browser.close();
  }
});

test("a legacy direct-connection link opens the Ethernet table", async (t) => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  t.after(() => browser.close());
  const page = await browser.newPage({ serviceWorkers: "block" });
  await fixture(page);
  await page.goto(url + "?exit=wan-a");

  const ethernet = page.getByRole("table", { name: "Ethernet", exact: true });
  const row = ethernet.getByRole("row").filter({
    has: page.getByRole("rowheader", { name: "wan-a", exact: true }),
  });
  await expect(
    row.getByRole("button", {
      name: "Редактировать подключение wan-a",
      exact: true,
    }),
  ).toBeVisible();
  await expect(row.getByRole("link")).toHaveCount(0);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("renaming an Ethernet connection updates its row and survives a reload", async (t) => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  t.after(() => browser.close());
  const page = await browser.newPage({ serviceWorkers: "block" });
  const { state } = await fixture(page);
  await page.goto(url);

  const ethernet = page.getByRole("table", { name: "Ethernet", exact: true });
  const port = ethernet
    .getByRole("row")
    .filter({ has: page.getByRole("cell", { name: "eth0", exact: true }) });
  await port
    .getByRole("button", {
      name: "Редактировать подключение wan-a",
      exact: true,
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Редактировать прямое подключение",
  });
  const field = dialog.getByLabel("Название подключения", { exact: true });
  await expect(field).toHaveValue("wan-a");
  const label = "Домашний интернет";
  await field.fill(label);
  await expect(field).toHaveValue(label);
  await perform(page, "PUT", "/api/connections/wan-a/name", () =>
    dialog.getByRole("button", { name: "Сохранить", exact: true }).click(),
  );
  assert.deepEqual(state.writes, [
    {
      method: "PUT",
      pathname: "/api/connections/wan-a/name",
      data: { name: label },
    },
  ]);
  await expect(dialog).toBeHidden();
  await expect(port.getByRole("rowheader")).toHaveText(label);
  await page.reload();
  await expect(port.getByRole("rowheader")).toHaveText(label);
});

test("selecting a named Ethernet transport saves its routing ID in the VPN profile", async (t) => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  t.after(() => browser.close());
  const page = await browser.newPage({ serviceWorkers: "block" });
  const label = "Домашний интернет";
  const { state } = await fixture(page, { directName: label });
  await page.goto(url);

  const editor = await edit(page, storedID, "existing");
  await editor.locator("#underlay-trigger").click();
  await editor.getByRole("checkbox", { name: label, exact: true }).check();
  await perform(page, "PUT", "/api/awg/" + storedID, () =>
    editor.getByRole("button", { name: "Сохранить", exact: true }).click(),
  );
  assert.equal(state.writes.length, 1);
  assert.deepEqual(state.writes[0].data.underlays, ["wan-a"]);
});

test("manual Wi-Fi setup uses the selected radio, band, SSID and password, and lists only public fields", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    const { state } = await fixture(page);
    await perform(page, "GET", "/api/physical-connections", () =>
      page.goto(url),
    );
    const list = page.getByRole("table", { name: "Wi-Fi", exact: true });
    await page
      .getByRole("button", { name: "Добавить Wi-Fi", exact: true })
      .click();
    const dialog = page.getByRole("dialog", {
      name: "Новое подключение Wi-Fi",
    });
    await dialog.getByLabel("Адаптер", { exact: true }).selectOption("wlan1");
    await dialog.getByLabel("Диапазон", { exact: true }).selectOption("5");
    await dialog.getByLabel("SSID", { exact: true }).fill("QA network");
    await dialog.getByLabel("Защита", { exact: true }).selectOption("wpa-psk");
    const password = dialog.getByLabel("Пароль", { exact: true });
    assert.equal(await password.getAttribute("type"), "password");
    await password.fill("synthetic-passphrase");
    await perform(page, "POST", "/api/wifi-connections", () =>
      dialog.getByRole("button", { name: "Сохранить", exact: true }).click(),
    );
    await dialog.waitFor({ state: "hidden" });
    await list.getByText("QA network", { exact: true }).waitFor();
    assert.deepEqual(state.writes[0].data, {
      interfaceName: "wlan1",
      band: "5",
      ssid: "QA network",
      security: "wpa-psk",
      password: "synthetic-passphrase",
    });
    await perform(page, "GET", "/api/physical-connections", () =>
      page.reload(),
    );
    await list.getByText("QA network", { exact: true }).waitFor();
    assert.doesNotMatch(await list.innerText(), /synthetic-passphrase/);
    await list
      .getByRole("button", { name: "Редактировать подключение QA network" })
      .click();
    const edit = page.getByRole("dialog", {
      name: "Редактировать подключение Wi-Fi",
    });
    assert.equal(
      await edit.getByLabel("Пароль", { exact: true }).inputValue(),
      "",
    );
    await edit.getByLabel("Диапазон", { exact: true }).selectOption("2.4");
    const path = "/api/wifi-connections/" + wifiID;
    await perform(page, "PUT", path, () =>
      edit.getByRole("button", { name: "Сохранить", exact: true }).click(),
    );
    await edit.waitFor({ state: "hidden" });
    assert.ok(!Object.hasOwn(state.writes.at(-1).data, "password"));
    await list.getByText("2,4 ГГц", { exact: true }).waitFor();
    page.once("dialog", (confirmation) => confirmation.accept());
    await perform(page, "DELETE", path, () =>
      list
        .getByRole("button", { name: "Удалить подключение QA network" })
        .click(),
    );
    await list
      .getByText("QA network", { exact: true })
      .waitFor({ state: "detached" });
  } finally {
    await browser.close();
  }
});

test("Wi-Fi setup cannot be submitted when a gateway has no radio", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    const { state } = await fixture(page, { hasRadio: false });
    await perform(page, "GET", "/api/physical-connections", () =>
      page.goto(url),
    );
    await page
      .getByText("Wi-Fi-адаптеры не обнаружены", { exact: true })
      .waitFor();
    const add = page.getByRole("button", {
      name: "Добавить Wi-Fi",
      exact: true,
    });
    if ((await add.isVisible()) && (await add.isEnabled())) {
      await add.click();
      assert.ok(
        await page
          .getByRole("dialog")
          .getByRole("button", { name: "Сохранить", exact: true })
          .isDisabled(),
      );
    }
    assert.equal(state.writes.length, 0);
  } finally {
    await browser.close();
  }
});

test("a failed physical inventory read appears in a PrimeNG error toast", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    await fixture(page);
    await page.route("**/api/physical-connections", (route) =>
      route.fulfill({ status: 503, json: {} }),
    );
    await page.goto(url);
    const message = "Не удалось обновить список физических подключений.";
    await page
      .locator("p-toast .gateway-toast-error")
      .getByText(message, { exact: true })
      .waitFor();
    assert.equal(await page.getByText(message, { exact: true }).count(), 1);
  } finally {
    await browser.close();
  }
});

test("Hysteria 2 imports a YAML and PEM pair, preserves the secret on rename and deletes the profile", async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_BIN,
  });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    page.setDefaultTimeout(7000);
    await fixture(page);
    const id = randomUUID();
    let record;
    let password;
    let detailReads = 0;
    const writes = [];
    await page.route("**/api/hysteria2**", async (route) => {
      const req = route.request();
      if (req.method() === "GET") {
        if (new URL(req.url()).pathname === "/api/hysteria2/" + id) {
          detailReads++;
          return route.fulfill({
            json: { ...record, password },
            headers: { "Cache-Control": "no-store" },
          });
        }
        return route.fulfill({ json: record ? [record] : [] });
      }
      if (req.method() === "DELETE") {
        record = undefined;
        return route.fulfill({ status: 204 });
      }
      const body = req.postDataJSON();
      writes.push(body);
      const { password: replacement, ...publicData } = body;
      password = replacement;
      record = {
        ...record,
        ...publicData,
        activeUnderlay: publicData.underlays.at(-1),
        id,
        priority: 1,
      };
      return route.fulfill({ json: record });
    });
    await page.goto(url);
    await page.getByRole("button", { name: "Добавить", exact: true }).click();
    await page
      .getByRole("menuitem", { name: "Hysteria 2", exact: true })
      .click();
    const dialog = page.getByRole("dialog");
    await dialog.waitFor();
    await page.keyboard.press("Escape");
    const opener = page.getByRole("button", { name: "Добавить", exact: true });
    await expect(opener).toBeFocused();
    await opener.press("Enter");
    await page.waitForFunction(() =>
      document.activeElement?.closest('[role="menu"]'),
    );
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await dialog.getByLabel("Название подключения").fill("Тест Hysteria");
    const picker = dialog.locator("#underlay-trigger");
    await expect(picker).toContainText("Любое интернет-подключение");
    await picker.press("Enter");
    await dialog
      .getByRole("checkbox", { name: "wan-b", exact: true })
      .press("Space");
    await dialog
      .getByRole("checkbox", { name: "existing", exact: true })
      .press("Space");
    await dialog.getByRole("button", { name: "Выше: existing" }).press("Enter");
    await expect(picker).toContainText("existing → wan-b");
    await picker.press("Enter");
    await dialog.getByLabel("Импорт YAML").setInputFiles({
      name: "demo.yaml",
      mimeType: "text/yaml",
      buffer: Buffer.from(
        "server: vpn.example:4443\nauth: demo-password\ntls: { ca: ca.pem }\nsocks5: { listen: 127.0.0.1:1080 }",
      ),
    });
    await expect(
      dialog
        .locator("p-toast")
        .getByRole("alert")
        .filter({ hasText: /Локальный SOCKS5/ }),
    ).toBeVisible();
    await expect(dialog.getByLabel("Пароль", { exact: true })).toHaveAttribute(
      "type",
      "text",
    );
    await expect(dialog.getByLabel("Пароль", { exact: true })).toHaveValue(
      "demo-password",
    );
    const save = dialog.getByRole("button", { name: "Сохранить" });
    await expect(save).toBeDisabled();
    await dialog.getByLabel("Доверенный сертификат PEM").setInputFiles({
      name: "ca.pem",
      mimeType: "text/plain",
      buffer: Buffer.from(
        "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----",
      ),
    });
    await dialog
      .getByRole("button", { name: "Удалить сертификат" })
      .press("Enter");
    await expect(dialog.getByLabel("Доверенный сертификат PEM")).toBeVisible();
    await expect(save).toBeEnabled();
    await dialog.getByLabel("Доверенный сертификат PEM").setInputFiles({
      name: "replacement.pem",
      mimeType: "text/plain",
      buffer: Buffer.from(
        "-----BEGIN CERTIFICATE-----\nY2VydDI=\n-----END CERTIFICATE-----",
      ),
    });
    await perform(page, "POST", "/api/hysteria2", () => save.click());
    assert.match(writes[0].certificatePEM, /Y2VydDI=/);
    assert.equal(writes[0].server, "vpn.example");
    assert.equal(writes[0].port, 4443);
    assert.equal(writes[0].password, "demo-password");
    assert.deepEqual(writes[0].underlays, [storedID, "wan-b"]);
    await page.reload();
    const row = savedRow(page, "Тест Hysteria");
    await expect(
      row.getByRole("cell", { name: "wan-b", exact: true }),
    ).toBeVisible();
    assert.equal(detailReads, 0);
    record = { ...record, name: "Актуальное название" };
    await row.getByRole("button", { name: /Редактировать/ }).click();
    await expect(dialog.getByLabel("Пароль", { exact: true })).toHaveValue(
      "demo-password",
    );
    await expect(dialog.getByLabel("Пароль", { exact: true })).toHaveAttribute(
      "type",
      "text",
    );
    assert.equal(detailReads, 1);
    await expect(dialog.getByLabel("Название подключения")).toHaveValue(
      "Актуальное название",
    );
    await expect(dialog.getByLabel("Доверенный сертификат PEM")).toHaveCount(0);
    await dialog
      .getByText("Показать сертификат", { exact: true })
      .press("Enter");
    await expect(
      dialog.getByLabel("Сертификат PEM", { exact: true }),
    ).toHaveText(writes[0].certificatePEM);
    await dialog
      .getByText("Показать сертификат", { exact: true })
      .press("Enter");
    const downloaded = page.waitForEvent("download");
    await dialog
      .getByRole("button", { name: "Скачать сертификат" })
      .press("Enter");
    assert.equal(
      await readFile(await (await downloaded).path(), "utf8"),
      writes[0].certificatePEM,
    );
    await dialog
      .getByRole("button", { name: "Удалить сертификат" })
      .press("Enter");
    await expect(dialog.getByLabel("Доверенный сертификат PEM")).toBeVisible();
    await picker.press("Enter");
    await dialog
      .getByRole("checkbox", { name: "Любое интернет-подключение" })
      .press("Space");
    await picker.press("Enter");
    await dialog.getByLabel("Название подключения").fill("Резерв");
    await perform(page, "PUT", "/api/hysteria2/" + id, () => save.click());
    assert.equal(writes[1].password, "demo-password");
    assert.equal(writes[1].certificatePEM, "");
    assert.deepEqual(writes[1].underlays, []);
    await expect(savedRow(page, "Резерв")).toContainText(
      "Любое интернет-подключение",
    );
    page.once("dialog", (d) => d.accept());
    await perform(page, "DELETE", "/api/hysteria2/" + id, () =>
      savedRow(page, "Резерв")
        .getByRole("button", { name: /Удалить/ })
        .click(),
    );
    await expect(savedRow(page, "Резерв")).toHaveCount(0);
  } finally {
    await browser.close();
  }
});
