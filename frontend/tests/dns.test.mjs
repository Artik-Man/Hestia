import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalDomain,
  samePolicy,
  validSettings,
  validSnapshot,
  validWarm,
} from "../src/routes/dns/dns-validation.ts";
const settings = {
  threshold: 5,
  automaticEnabled: true,
  windowHours: 24,
  intervalMinutes: 10,
  retentionSeconds: 60,
  serveStale: true,
  staleWindowSeconds: 60,
};
const policy = {
  settings,
  manual: ["a.example", "b.example"],
  exclusions: ["b.example"],
};

/** Verifies gateway-compatible domains and rejects masks, address literals and invalid UTF-8 host spellings. */
test("canonicalizes exact ASCII domains and prevents ambiguous list input", () => {
  assert.equal(
    canonicalDomain(" XN--E1AFMKFD.example. "),
    "xn--e1afmkfd.example",
  );
  for (const name of [
    "*.example",
    "::1",
    "127.0.0.1",
    "https://a.example",
    "K.example",
    "a..b",
    "bad-",
  ])
    assert.equal(canonicalDomain(name), null);
  assert.ok(validSnapshot({ policy, revision: 0 }));
  assert.ok(
    !validSnapshot({
      policy: { ...policy, manual: ["a.example", "a.example"] },
      revision: 1,
    }),
  );
});

/** Verifies acknowledgements must match requested settings and memberships despite canonical server ordering. */
test("acknowledges only the desired policy and enforces stale retention", () => {
  assert.ok(
    samePolicy({ ...policy, manual: ["b.example", "a.example"] }, policy),
  );
  assert.ok(!samePolicy({ ...policy, exclusions: [] }, policy));
  assert.ok(
    !samePolicy({ ...policy, settings: { ...settings, threshold: 6 } }, policy),
  );
  assert.ok(!validSettings({ ...settings, staleWindowSeconds: 61 }));
  assert.ok(
    validSettings({ ...settings, serveStale: false, staleWindowSeconds: 0 }),
  );
});

/** Verifies malformed observations cannot appear as a valid empty or positive result. */
test("separates valid empty telemetry from unavailable or malformed observations", () => {
  const report = {
    policyRevision: 0,
    observedAt: "2026-01-01T12:00:00Z",
    automatic: [],
  };
  assert.ok(validWarm(report));
  const aboveLimit = Array.from({ length: 32769 }, (_, i) => ({
    domain: "d" + i + ".example",
    clientRequests: 1,
  }));
  assert.ok(!validWarm({ ...report, automatic: aboveLimit }));
  assert.ok(!validWarm(null));
  assert.ok(
    !validWarm({ ...report, automatic: [{ domain: "a", clientRequests: -1 }] }),
  );
});

/** Covers backwards-compatible telemetry, true zero demand and impossible retry counters at the network boundary. */
test("accepts optional client UDP counts without accepting corrupt retry rates", () => {
  const report = {
    observedAt: "2026-11-05T00:00:00Z",
    policyRevision: 1,
    automatic: [],
  };
  for (const clientUdp of [
    undefined,
    { attempts: 0, retriedAttempts: 0, unclassifiedAttempts: 0 },
    { attempts: 4, retriedAttempts: 1, unclassifiedAttempts: 2 },
    { attempts: 3, retriedAttempts: 0, unclassifiedAttempts: 3 },
  ])
    assert.ok(validWarm({ ...report, clientUdp }));
  for (const clientUdp of [
    null,
    {},
    { attempts: 1, retriedAttempts: 0 },
    { attempts: 3, retriedAttempts: 1, unclassifiedAttempts: 2 },
    { attempts: 2, retriedAttempts: 0, unclassifiedAttempts: 3 },
    { attempts: 0, retriedAttempts: 1, unclassifiedAttempts: 0 },
    { attempts: 3, retriedAttempts: 3, unclassifiedAttempts: 0 },
    { attempts: 3.5, retriedAttempts: 0, unclassifiedAttempts: 0 },
    {
      attempts: Number.MAX_SAFE_INTEGER + 1,
      retriedAttempts: 0,
      unclassifiedAttempts: 0,
    },
  ])
    assert.ok(!validWarm({ ...report, clientUdp }));
});
