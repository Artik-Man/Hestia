import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const run = promisify(execFile);
const bundle = new URL("../../dist/hestia/browser/", import.meta.url);
const snapshot = {
  groups: [{ id: "fi", isDefault: true, exits: [] }],
  lists: [],
};

/** serve provides the production bundle and a local snapshot for the profile-switch regression. */
async function serve(req, res) {
  const path = new URL(req.url, "http://localhost").pathname;
  if (path === "/api/navigation" || path === "/api/groups-and-rules") {
    res.setHeader("Content-Type", "application/json");
    res.end(
      JSON.stringify(
        path === "/api/navigation" ? { grafanaUrl: "" } : snapshot,
      ),
    );
    return;
  }
  try {
    if (path === "/") {
      const page = await readFile(new URL("index.html", bundle), "utf8");
      res.setHeader("Content-Type", "text/html");
      res.end(
        page.replace(
          "</body>",
          '<script type="module" src="/exercise.mjs"></script></body>',
        ),
      );
      return;
    }
    const filename = path.slice(1);
    if (!/^[\w.-]+$/.test(filename)) {
      res.writeHead(404).end();
      return;
    }
    const asset =
      filename === "exercise.mjs"
        ? new URL("./exercise.mjs", import.meta.url)
        : new URL(filename, bundle);
    const data = await readFile(asset);
    res.setHeader(
      "Content-Type",
      filename.endsWith(".css")
        ? "text/css"
        : filename.endsWith(".svg")
          ? "image/svg+xml"
          : "text/javascript",
    );
    res.end(data);
  } catch {
    res.writeHead(404).end();
  }
}

test("shared WireGuard controls accept new values after switching to AmneziaWG", async () => {
  const profile = await mkdtemp(join(tmpdir(), "hestia-profile-browser-"));
  const server = createServer(serve);
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { stdout } = await run(
      process.env.CHROME_BIN || "google-chrome",
      [
        "--headless",
        "--disable-gpu",
        "--disable-background-networking",
        "--no-first-run",
        "--user-data-dir=" + profile,
        "--virtual-time-budget=6000",
        "--dump-dom",
        "http://127.0.0.1:" + server.address().port + "/#/connections",
      ],
      { timeout: 30000, maxBuffer: 2_000_000 },
    );
    const marker = stdout.match(/data-profile-test="([^"]*)"/)?.[1];
    assert.equal(marker, "passed");
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(profile, { force: true, recursive: true });
  }
});
