import type { AWGUnderlayCandidate } from "./api/generated/model/aWGUnderlayCandidate";
import type { AWGConnection } from "./api/generated/model/aWGConnection";

/** isUnderlayCandidate accepts only supported public transport records with a gateway identifier. */
export function isUnderlayCandidate(
  value: unknown,
): value is AWGUnderlayCandidate {
  return (
    typeof value === "object" &&
    value !== null &&
    "id" in value &&
    typeof value.id === "string" &&
    /^[a-z][a-z0-9-]{0,62}$/.test(value.id) &&
    (!("name" in value) ||
      (typeof value.name === "string" &&
        value.name.length > 0 &&
        value.name === value.name.trim() &&
        !/\p{Cc}/u.test(value.name) &&
        [...value.name].length <= 80)) &&
    "type" in value &&
    (value.type === "direct" ||
      value.type === "wireguard" ||
      value.type === "amneziawg")
  );
}

/** isUnderlayOrder checks the optional transport priority list received from the gateway. */
export function isUnderlayOrder(
  value: unknown,
  owner: string,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length <= 64 &&
    value.every(
      (id: unknown) =>
        typeof id === "string" &&
        id !== owner &&
        /^[a-z][a-z0-9-]{0,62}$/.test(id),
    ) &&
    new Set(value).size === value.length
  );
}

/** isAWGConnection validates public profile metadata before showing a gateway response. */
export function isAWGConnection(value: unknown): value is AWGConnection {
  if (typeof value !== "object" || value === null) return false;
  return (
    "id" in value &&
    typeof value.id === "string" &&
    /^[a-z][a-z0-9-]{0,62}$/.test(value.id) &&
    "group" in value &&
    typeof value.group === "string" &&
    /^[a-z][a-z0-9-]{0,62}$/.test(value.group) &&
    "priority" in value &&
    typeof value.priority === "number" &&
    Number.isInteger(value.priority) &&
    value.priority > 0 &&
    (!("underlays" in value) || isUnderlayOrder(value.underlays, value.id)) &&
    (!("activeUnderlay" in value) ||
      (typeof value.activeUnderlay === "string" &&
        "underlays" in value &&
        Array.isArray(value.underlays) &&
        value.underlays.includes(value.activeUnderlay))) &&
    "ipv6Blocked" in value &&
    typeof value.ipv6Blocked === "boolean" &&
    "status" in value &&
    (value.status === "ready" ||
      value.status === "checking" ||
      value.status === "configured" ||
      value.status === "error")
  );
}
