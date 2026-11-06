import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { resolve } from "node:path";
import test from "node:test";

// This local HTTP fixture intentionally stops rendering after creation so SIGTERM
// exercises the real UI helper's finally cleanup without touching any gateway.
test("UI interruption deletes its owned list before losing its API context", async () => {
  const lists = [];
  let child;
  let deleted = false;
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/api/groups-and-rules") {
      response.end(
        JSON.stringify({ lists, groups: [{ id: "default", exits: [] }] }),
      );
    } else if (
      request.url === "/api/domain-lists" &&
      request.method === "POST"
    ) {
      const value = {
        ...JSON.parse(body),
        id: "owned-local-list",
        group: "",
        enabled: false,
      };
      lists.push(value);
      response.writeHead(201).end(JSON.stringify(value));
      setTimeout(() => child.kill("SIGTERM"), 100);
    } else if (
      request.url === "/api/domain-lists/owned-local-list" &&
      request.method === "DELETE"
    ) {
      assert.deepEqual(JSON.parse(body), lists[0]);
      lists.length = 0;
      deleted = true;
      response.writeHead(204).end();
    } else {
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.end(`<!doctype html><button onclick="document.querySelector('dialog').showModal()">Создать список</button>
<dialog aria-label="Новый список"><label>Название списка<input id="name"></label><label>Маски, по одной в строке<textarea id="masks"></textarea></label><button onclick="fetch('/api/domain-lists',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:document.querySelector('#name').value,masks:[document.querySelector('#masks').value],group:''})})">Сохранить</button></dialog>`);
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const repo = resolve(import.meta.dirname, "../../..");
  let timer;
  try {
    const childEnv = { ...process.env };
    delete childEnv.NODE_TEST_CONTEXT;
    child = spawn(
      process.execPath,
      [resolve(import.meta.dirname, "ui_accept.mjs")],
      {
        env: {
          ...childEnv,
          HESTIA_VALIDATION_REPO: repo,
          HESTIA_E2E_URL: `http://127.0.0.1:${server.address().port}`,
        },
        stdio: "pipe",
      },
    );
    let output = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      output += chunk;
    });
    const code = await new Promise((done, reject) => {
      timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error("UI cancellation fixture timed out: " + output));
      }, 20000);
      child.once("error", reject);
      child.once("exit", done);
    });
    assert.notEqual(code, 0);
    assert.equal(deleted, true);
    assert.deepEqual(lists, []);
  } finally {
    clearTimeout(timer);
    if (child && child.exitCode === null) child.kill("SIGKILL");
    await new Promise((done) => server.close(done));
  }
});
