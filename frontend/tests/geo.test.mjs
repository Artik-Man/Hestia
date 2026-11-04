import test from "node:test";
import assert from "node:assert/strict";
import { previewCountry } from "../src/geo-policy.ts";

const groups = [{ id: "fallback", isDefault: true, exits: [] }];
const policy = {
  countries: [{ country: "DE", group: "country" }],
  blocks: [
    { name: "West", countries: ["DE", "FR"], group: "first" },
    { name: "Europe", countries: ["DE", "FR"], group: "second" },
  ],
  world: "rest",
};

test("individual country wins over overlapping blocks", () => {
  assert.deepEqual(previewCountry("DE", policy, groups), {
    reason: "country",
    group: "country",
  });
});
test("overlapping blocks follow draft order", () => {
  assert.equal(previewCountry("FR", policy, groups).group, "first");
  assert.equal(
    previewCountry(
      "FR",
      { ...policy, blocks: [...policy.blocks].reverse() },
      groups,
    ).group,
    "second",
  );
});
test("unknown country uses the default even with a rest-of-world rule", () => {
  assert.deepEqual(previewCountry("", policy, groups), {
    reason: "unknown",
    group: "fallback",
  });
  assert.deepEqual(previewCountry("BR", policy, groups), {
    reason: "world",
    group: "rest",
  });
  assert.deepEqual(previewCountry("BR", { ...policy, world: "" }, groups), {
    reason: "default",
    group: "fallback",
  });
});
