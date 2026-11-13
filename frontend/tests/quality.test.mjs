import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isQualityReport,
  isQualitySettings,
  validCheck,
} from "../src/routes/quality/quality-observations.ts";

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
        settings,
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
  check.protocol = "ICMP";
  check.unsupported = true;
  assert.equal(isQualityReport(body), true);
  check.unsupported = "false";
  assert.equal(isQualityReport(body), false);
  check.unsupported = false;
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
    groups: [{ id: "fi", name: "", settings, connections: [connection] }],
  };
  assert.equal(isQualityReport(report), true);
  target.dnsResponseCodes = { 2: 1, 3: 1 };
  assert.equal(isQualityReport(report), true);
  for (const breakdown of [{ 2: 3 }, { 0: 2 }, { 4096: 2 }, { 3: "2" }, null]) {
    target.dnsResponseCodes = breakdown;
    assert.equal(isQualityReport(report), false);
  }
});

test("validates ICMP, resolver and TLS service check fields independently", () => {
  const tcp = {
    protocol: "TCP",
    targets: ["1.1.1.1:443"],
    intervalSeconds: 30,
    timeoutSeconds: 3,
  };
  const icmp = {
    ...tcp,
    protocol: "ICMP",
    targets: ["1.1.1.1", "2606:4700:4700::1111"],
  };
  const dns = { ...udp, protocol: "DNS", targets: ["8.8.8.8:53"] };
  const https = {
    ...tcp,
    protocol: "HTTPS",
    serverName: "example.org",
    requestPath: "/health?region=fi",
  };
  const http3 = { ...https, protocol: "HTTP3" };
  assert.equal(
    isQualitySettings({
      windowMinutes: 60,
      checks: [udp, tcp, icmp, dns, https, http3],
    }),
    true,
  );
  for (const bad of [
    { ...icmp, targets: ["1.1.1.1:7"] },
    { ...dns, targets: ["1.1.1.1:443"] },
    { ...https, serverName: "" },
    { ...http3, requestPath: "//other.example/a" },
    { ...tcp, requestPath: "/" },
    { ...icmp, dnsName: "example.org" },
  ]) {
    assert.equal(
      isQualitySettings({ windowMinutes: 60, checks: [bad] }),
      false,
    );
  }
});

test("raw TCP targets are accepted only on input, including when TCP is the second saved check", () => {
  const tcp = {
    protocol: "TCP",
    targets: ["example.org", "1.1.1.1"],
    intervalSeconds: 30,
    timeoutSeconds: 3,
  };
  assert.equal(validCheck(tcp, true), true);
  assert.equal(isQualitySettings({ ...settings, checks: [udp, tcp] }), false);
  assert.equal(validCheck({ ...udp, targets: tcp.targets }, true), false);
});

/** Rejects missing or invalid settings in one group even when the legacy global seed is valid. */
test("quality reports require independently validated group settings", () => {
  const group = { id: "ru", name: "Россия", connections: [], settings };
  const report = {
    settings,
    capturedAt: "",
    groups: [
      group,
      { ...group, id: "world", settings: { windowMinutes: 90, checks: [] } },
    ],
  };
  assert.equal(isQualityReport(report), true);
  assert.equal(
    isQualityReport({ ...report, groups: [{ ...group, settings: undefined }] }),
    false,
  );
  assert.equal(
    isQualityReport({
      ...report,
      groups: [{ ...group, settings: { ...settings, windowMinutes: 0 } }],
    }),
    false,
  );
});
