import assert from "node:assert/strict";
import test from "node:test";
import { createSocket } from "node:dgram";
import { once } from "node:events";
import { chromium } from "playwright";

/** Sends the exact fixture DNS question on an existing loopback socket, retaining its source port for a retry. */
async function sendFixtureQuery(socket, port, packet) {
  const arrived = once(socket, "message", {
    signal: AbortSignal.timeout(3000),
  });
  socket.send(packet, port, "127.0.0.1");
  const [reply] = await arrived;
  assert.equal(reply.readUInt16BE(0), packet.readUInt16BE(0));
  assert.equal(reply.readUInt16BE(6), 1);
}

/** Checks automatic exclusion and reentry against a real worker heartbeat with exactly three prior client queries. */
test(
  "DNS worker restores automatic-only membership without further client queries",
  { timeout: 65000 },
  async () => {
    const url = new URL(process.env.HESTIA_DNS_BROWSER_FIXTURE);
    assert.equal(url.hostname, "127.0.0.1");
    const browser = await chromium.launch({
      executablePath: process.env.CHROME_BIN,
    });
    const listener = new URL("udp://" + process.env.HESTIA_DNS_WARM_LISTENER);
    assert.equal(listener.hostname, "127.0.0.1");
    const port = Number(listener.port),
      packet = Buffer.from(process.env.HESTIA_DNS_WARM_QUERY, "base64");
    const udp = createSocket("udp4");
    try {
      await sendFixtureQuery(udp, port, packet);
      const page = await browser.newPage();
      page.setDefaultTimeout(20000);
      await page.goto(new URL("/#/dns", url).href);
      const auto = page.getByRole("region", {
        name: "Автоматически добавленные",
      });
      const manual = page.getByRole("region", { name: "Добавленные вручную" });
      const excluded = page.getByRole("region", {
        name: "Чёрный список автопрогрева",
      });
      const name = "auto-only.example",
        row = auto.getByRole("listitem").filter({ hasText: name });
      const initial = (
        await (
          await page.request.get(new URL("/api/dns/policy", url).href)
        ).json()
      ).revision;
      assert.ok(Number.isInteger(initial));
      await row.getByText(/Запросов за окно:\s*3/).waitFor();
      await auto.getByText(/UDP без замеченного повтора — 100\s*%/).waitFor();
      await sendFixtureQuery(udp, port, packet);
      await manual.getByText("Домены вручную ещё не добавлены.").waitFor();

      await row
        .getByRole("button", { name: "В чёрный список: " + name })
        .click();
      await excluded.getByText(name, { exact: true }).waitFor();
      await auto
        .getByText("Автоматически добавленных доменов пока нет.")
        .waitFor();
      await auto.getByText(/UDP без замеченного повтора — 50\s*%/).waitFor();
      await auto.getByText(/всего попыток 2, потребовали повтора 1/).waitFor();
      const afterExclude = await page.request.get(
        new URL("/api/dns/warm", url).href,
      );
      assert.equal(afterExclude.status(), 200);
      const blocked = await afterExclude.json();
      assert.equal(blocked.policyRevision, initial + 1);
      assert.deepEqual(blocked.automatic, []);

      await excluded
        .getByRole("button", { name: "Снять исключение: " + name })
        .click();
      await row.getByText(/Запросов за окно:\s*3/).waitFor();
      await excluded.getByText("Исключений пока нет.").waitFor();
      await manual.getByText("Домены вручную ещё не добавлены.").waitFor();
      const afterRestore = await page.request.get(
        new URL("/api/dns/warm", url).href,
      );
      assert.equal(afterRestore.status(), 200);
      const restored = await afterRestore.json();
      assert.equal(restored.policyRevision, initial + 2);
      assert.deepEqual(restored.automatic, [
        { domain: name, clientRequests: 3 },
      ]);
    } finally {
      udp.close();
      await browser.close();
    }
  },
);
