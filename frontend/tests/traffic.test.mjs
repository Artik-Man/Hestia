import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validTrafficPage,
  validTrafficSettings,
} from "../src/routes/traffic/traffic-observations.ts";

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
  assert.ok(!validTrafficPage(page, 1, 500, "3"));
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
