import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isQualityReport,
  isQualitySettings,
} from "../src/quality-observations.ts";

const udp = {
  protocol: "UDP",
  targets: ["1.1.1.1:53", "8.8.8.8:53"],
  intervalSeconds: 30,
  timeoutSeconds: 3,
  dnsName: "example.com.",
};
const settings = { windowMinutes: 60, checks: [udp] };

test("editing checks supports deletion and rejects duplicate protocols or malformed UDP targets", () => {
  assert.equal(isQualitySettings(settings), true);
  assert.equal(isQualitySettings({ ...settings, checks: [] }), true);
  for (const checks of [
    [udp, udp],
    [{ ...udp, targets: ["1.1.1.1:53"] }],
    [{ ...udp, targets: ["dns.google:53", "8.8.8.8:53"] }],
    [{ ...udp, timeoutSeconds: 31 }],
  ]) {
    assert.equal(isQualitySettings({ ...settings, checks }), false);
  }
});

test("accepts a measured zero score and rejects inconsistent counters or counterfeit no-data scores", () => {
  const check = {
    protocol: "UDP",
    samples: 1,
    successes: 0,
    localErrors: 0,
    score: 0,
    targets: [],
  };
  const body = {
    settings,
    capturedAt: "2026-11-05T12:00:00Z",
    groups: [
      {
        id: "main",
        name: "Main",
        connections: [
          {
            id: "fi",
            available: true,
            active: false,
            result: { overall: 0, checks: [check] },
          },
        ],
      },
    ],
  };
  assert.equal(isQualityReport(body), true);
  check.score = null;
  assert.equal(isQualityReport(body), false);
  check.samples = 0;
  body.groups[0].connections[0].result.overall = null;
  assert.equal(isQualityReport(body), true);
  check.successes = 1;
  assert.equal(isQualityReport(body), false);
});

test("validates optional DNS response-code counters against the per-target error total", () => {
  const target = {
    target: "1.1.1.1:53",
    samples: 2,
    successes: 2,
    localErrors: 0,
    dnsErrors: 2,
    score: 100,
  };
  const check = {
    protocol: "UDP",
    samples: 2,
    successes: 2,
    localErrors: 0,
    score: 100,
    targets: [target],
  };
  const connection = {
    id: "test",
    available: true,
    active: true,
    result: { overall: 100, checks: [check] },
  };
  const report = {
    settings,
    capturedAt: "2026-11-05T12:00:00Z",
    groups: [{ id: "fi", name: "", connections: [connection] }],
  };
  assert.equal(isQualityReport(report), true);
  target.dnsResponseCodes = { 2: 1, 3: 1 };
  assert.equal(isQualityReport(report), true);
  for (const breakdown of [{ 2: 3 }, { 0: 2 }, { 4096: 2 }, { 3: "2" }, null]) {
    target.dnsResponseCodes = breakdown;
    assert.equal(isQualityReport(report), false);
  }
});
