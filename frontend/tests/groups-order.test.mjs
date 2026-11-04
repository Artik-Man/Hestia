import test from "node:test";
import assert from "node:assert/strict";
import {
  moveTo,
  matchesOrder,
  reconcile,
  sourceOrder,
} from "../src/groups-order.ts";

const source = [
  { id: "fi", exits: ["fi1", "fi2"] },
  { id: "ru", exits: ["ru1"] },
  { id: "empty", exits: [] },
];
const desired = moveTo(source, 2, 0);

test("confirmation checks all group IDs and every exit in order", () => {
  assert.equal(matchesOrder(desired, desired), true);
  for (const invalid of [
    [],
    source,
    [...desired, source[0]],
    [desired[0], { id: "fi", exits: ["fi2", "fi1"] }, desired[2]],
    [desired[0], null, desired[2]],
    {},
    null,
  ])
    assert.equal(matchesOrder(invalid, desired), false);
});

test("loading and health-only changes keep unsaved working order and CAS baseline", () => {
  const draft = { baseline: source, order: desired, changedSource: false };
  const groups = source.map((group) => ({
    ...group,
    isDefault: group.id === "fi",
    exits: group.exits.map((id) => ({ id, available: true })),
  }));
  groups[0].exits[0].available = false;
  assert.equal(reconcile(null, draft), draft);
  assert.equal(reconcile(sourceOrder(groups), draft), draft);
});

test("concurrent changes pin the expected revision and require review; observed proposal is clean", () => {
  const draft = { baseline: source, order: desired, changedSource: false };
  const concurrent = moveTo(source, 1, 0);
  assert.deepEqual(reconcile(concurrent, draft), {
    ...draft,
    changedSource: true,
  });
  assert.deepEqual(reconcile(desired, draft), {
    baseline: desired,
    order: desired,
    changedSource: false,
  });
});

test("out-of-range keyboard moves preserve order", () => {
  assert.equal(moveTo(source, 0, -1), source);
  assert.equal(moveTo(source, 2, 3), source);
  assert.deepEqual(
    desired.map((group) => group.id),
    ["empty", "fi", "ru"],
  );
  assert.equal(source[0].id, "fi");
});
