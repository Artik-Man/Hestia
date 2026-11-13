import type { AWGUnderlayCandidate } from "../services/api/generated/model/aWGUnderlayCandidate";
import type { AWGConnection } from "../services/api/generated/model/aWGConnection";

const platformInputIDs: ReadonlySet<string> = new Set([
  "wg-keenetic",
  "keenetic-opkgtun",
]);

/** isConnectionUUID recognizes canonical UUIDs that must stay out of user-facing labels. */
export function isConnectionUUID(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(
    value,
  );
}

/** isExitID accepts a routing UUID or a configured gateway exit identifier. */
function isExitID(value: string): boolean {
  return isConnectionUUID(value) || /^[a-z][a-z0-9-]{0,62}$/u.test(value);
}

/** isConnectionName checks the gateway's public display name contract in Unicode code points. */
export function isConnectionName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value === value.trim() &&
    !/\p{Cc}/u.test(value) &&
    [...value].length <= 80
  );
}

/** isUnderlayCandidate accepts only supported public transport records with a gateway identifier. */
export function isUnderlayCandidate(
  value: unknown,
): value is AWGUnderlayCandidate {
  return (
    typeof value === "object" &&
    value !== null &&
    (!("enabled" in value) || typeof value.enabled === "boolean") &&
    "id" in value &&
    typeof value.id === "string" &&
    isExitID(value.id) &&
    (!("name" in value) || isConnectionName(value.name)) &&
    "type" in value &&
    (value.type === "direct" ||
      value.type === "wireguard" ||
      value.type === "amneziawg" ||
      value.type === "hysteria2") &&
    (!("role" in value) ||
      value.role === undefined ||
      value.role === "input" ||
      value.role === "output")
  );
}

/** isUserSelectableUnderlay excludes platform ingress by role or stable ID while retaining unknown saved IDs. */
export function isUserSelectableUnderlay(
  id: string,
  candidate: AWGUnderlayCandidate | undefined,
): boolean {
  return candidate?.role !== "input" && !platformInputIDs.has(id);
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
      (id: unknown) => typeof id === "string" && id !== owner && isExitID(id),
    ) &&
    new Set(value).size === value.length
  );
}

/** isAWGConnection validates public profile metadata before showing a gateway response. */
export function isAWGConnection(value: unknown): value is AWGConnection {
  if (typeof value !== "object" || value === null) return false;
  return (
    (!("enabled" in value) || typeof value.enabled === "boolean") &&
    "id" in value &&
    typeof value.id === "string" &&
    isExitID(value.id) &&
    "name" in value &&
    isConnectionName(value.name) &&
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
