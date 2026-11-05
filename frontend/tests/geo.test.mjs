import test from "node:test";
import assert from "node:assert/strict";
import {
  initializeCountryMap,
  readCountryMap,
  regionCodes,
} from "../src/core/models/geo-policy.ts";

/** Verifies the initial map covers each country exactly once and starts disabled. */
test("a new map assigns every country to the initial default", () => {
  const map = initializeCountryMap("first");
  assert.equal(map.enabled, false);
  assert.equal(regionCodes.length, 249);
  assert.deepEqual(
    Object.keys(map.assignments).sort(),
    [...regionCodes].sort(),
  );
  assert.deepEqual(new Set(Object.values(map.assignments)), new Set(["first"]));
});

/** Verifies restored state preserves both the switch and individual assignments. */
test("restoring a local map preserves every explicit selection", () => {
  const map = initializeCountryMap("first");
  const edited = {
    enabled: true,
    assignments: { ...map.assignments, DE: "second" },
  };
  assert.deepEqual(readCountryMap(JSON.stringify(edited)), edited);
});
