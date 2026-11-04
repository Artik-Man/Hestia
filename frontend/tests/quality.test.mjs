import { test } from "node:test";
import assert from "node:assert/strict";
import { summarizeProbes } from "../src/quality-observations.ts";

test("a local probe error does not count as a lost packet", () => {
  const sample = {
    time: "2026-11-04T00:00:00Z",
    group: "fi",
    exit: "main",
    target: "echo",
    protocol: "UDP",
    outcome: "timeout",
    latencyMs: null,
  };
  const data = [
    sample,
    { ...sample, outcome: "local-error" },
    { ...sample, exit: "reserve", outcome: "local-error" },
    { ...sample, protocol: "TCP", outcome: "reply", latencyMs: 15 },
    { ...sample, target: "other" },
    { ...sample, time: "2026-11-03T23:59:00Z" },
  ];
  const at = Date.parse(sample.time);
  const totals = summarizeProbes(data, "fi", "echo", "UDP", at, at);
  assert.deepEqual(totals.get("main"), {
    samples: 1,
    timeouts: 1,
    localErrors: 1,
    meanLatencyMs: null,
  });
  assert.deepEqual(totals.get("reserve"), {
    samples: 0,
    timeouts: 0,
    localErrors: 1,
    meanLatencyMs: null,
  });
  assert.equal(totals.get("missing"), undefined);
});
