import type { Exit } from "./api/generated/model/exit";
import type { Group } from "./api/generated/model/group";
import type { RuleList } from "./api/generated/model/ruleList";
import type { Snapshot } from "./api/generated/model/snapshot";

/** isRecord permits property inspection only on non-null JSON objects. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** isExit verifies the identifier and the boolean availability before display. */
function isExit(value: unknown): value is Exit {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.available === "boolean"
  );
}

/** isGroup requires an ordered array containing only valid exits. */
function isGroup(value: unknown): value is Group {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.isDefault === "boolean" &&
    Array.isArray(value.exits) &&
    value.exits.every(isExit)
  );
}

/** isRuleList validates all list fields, including each mask, without dropping unassigned lists. */
function isRuleList(value: unknown): value is RuleList {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    typeof value.group === "string" &&
    typeof value.enabled === "boolean" &&
    Array.isArray(value.masks) &&
    value.masks.every((mask: unknown) => typeof mask === "string")
  );
}

/** isSnapshot accepts complete, typed API responses before Angular renders their contents. */
export function isSnapshot(value: unknown): value is Snapshot {
  return (
    isRecord(value) &&
    Array.isArray(value.groups) &&
    value.groups.every(isGroup) &&
    Array.isArray(value.lists) &&
    value.lists.every(isRuleList)
  );
}
