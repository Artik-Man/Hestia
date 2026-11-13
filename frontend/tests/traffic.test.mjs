import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validTrafficPage,
  validTrafficSettings,
} from "../src/routes/traffic/traffic-observations.ts";
import { trafficOutcomeName } from "../src/core/models/traffic-outcome.ts";

/** Keeps journal outcomes focused on the selected connector, explicit block, or missing decision. */
test("traffic outcomes show selected outputs and distinguish blocked from unknown", () => {
  const resolveName = (id) =>
    id === "awg-id" ? "Zarubin" : "Название недоступно";
  const event = { connection: "awg-id", kind: "unconfirmed" };
  assert.equal(trafficOutcomeName(event, resolveName), "Zarubin");
  assert.equal(
    trafficOutcomeName(
      { ...event, connection: "keenetic-uplink" },
      resolveName,
    ),
    "Название недоступно",
  );
  for (const name of ["Мой провайдер", "Новое имя"]) {
    assert.equal(
      trafficOutcomeName(
        { ...event, connection: "keenetic-uplink" },
        () => name,
      ),
      name,
    );
  }
  assert.equal(
    trafficOutcomeName({ kind: "blocked" }, resolveName),
    "Заблокировано",
  );
  assert.equal(
    trafficOutcomeName({ kind: "unconfirmed" }, resolveName),
    "Не определено",
  );
});

/** Covers bounded viewport allocation, stable snapshots and rejection of malformed evidence. */
test("traffic page validates the window and the source before accepting observations", () => {
  const event = {
    id: "1",
    time: "2026-11-05T12:00:00Z",
    address: "2001:db8::9",
    port: 443,
    kind: "unconfirmed",
    protocol: "UDP",
  };
  const page = {
    total: 2,
    lost: 0,
    events: [event],
    outputs: [],
    snapshot: "2",
    sourceAvailable: false,
  };
  assert.ok(validTrafficPage(page, 1, 500, "2"));
  assert.ok(
    validTrafficPage(
      { ...page, events: [{ ...event, protocol: "QUIC" }] },
      1,
      500,
    ),
  );
  assert.ok(
    !validTrafficPage(
      { ...page, events: [{ ...event, protocol: "ICMP" }] },
      1,
      500,
    ),
  );
  assert.ok(!validTrafficPage(page, 1, 500, "3"));
  for (const country of ["", "Russia", null, 12]) {
    assert.ok(
      !validTrafficPage({ ...page, events: [{ ...event, country }] }, 1, 500),
    );
  }
  assert.ok(
    !validTrafficPage(
      { ...page, events: [{ ...event, country: "SE", countryName: 123 }] },
      1,
      500,
    ),
  );
  assert.ok(
    !validTrafficPage(
      {
        ...page,
        events: [
          { ...event, address: "", fakeIP: "198.18.0.1", country: "RU" },
        ],
      },
      1,
      500,
    ),
  );
  assert.ok(
    !validTrafficPage({ ...page, lastInterruption: "unknown" }, 1, 500),
  );
  assert.ok(!validTrafficPage({ ...page, total: 2 ** 32 }, 1, 500));
  assert.ok(
    !validTrafficPage(
      { ...page, events: [{ ...event, kind: "observed" }] },
      1,
      500,
    ),
  );
  assert.ok(!validTrafficPage(page, 0, 500));
  assert.ok(
    validTrafficPage(
      { ...page, events: [{ ...event, address: "", domain: "example.org" }] },
      1,
      500,
    ),
  );
});

/** Covers both limits and rejects invalid or malformed wire-level quantities. */
test("journal settings require bounded positive whole numbers", () => {
  assert.ok(validTrafficSettings({ maxMB: 1024, retentionHours: 24 }));
  assert.ok(!validTrafficSettings({ maxMB: 0, retentionHours: 24 }));
  assert.ok(!validTrafficSettings({ maxMB: 1024, retentionHours: 1.5 }));
});
