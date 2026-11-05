import test from "node:test";
import assert from "node:assert/strict";
import { isCountryMap, regionCodes } from "../src/core/models/geo-policy.ts";

/** Checks the versioned API snapshot has every supported country and one explicit assignment per code. */
test("country map accepts a complete versioned response", () => {
  assert.equal(regionCodes.length, 249);
  assert.equal(new Set(regionCodes).size, 249);
  const assignments = Object.fromEntries(
    regionCodes.map((code) => [code, "first"]),
  );
  assert.equal(
    isCountryMap({ version: "v1", enabled: false, assignments }),
    true,
  );
  delete assignments.DE;
  assert.equal(
    isCountryMap({ version: "v1", enabled: true, assignments }),
    false,
  );
});

/** Rejects malformed network responses before their selections reach the screen. */
test("country map rejects corrupt assignments, versions and switches", () => {
  const assignments = Object.fromEntries(
    regionCodes.map((code) => [code, "first"]),
  );
  const valid = { enabled: false, version: "v1", assignments };
  for (const invalid of [
    null,
    { ...valid, version: "" },
    { ...valid, enabled: "false" },
    { ...valid, assignments: { ...assignments, DE: "" } },
    { ...valid, assignments: { ...assignments, XX: "second" } },
  ])
    assert.equal(isCountryMap(invalid), false);
});
