import type { DNSPolicySnapshot as CheckedSnapshot } from "../../core/services/api/generated/model/dNSPolicySnapshot";
import type { DNSWarmReport as CheckedWarm } from "../../core/services/api/generated/model/dNSWarmReport";
import type { DNSSettings as DnsSettings } from "../../core/services/api/generated/model/dNSSettings";
import type { Policy as DnsPolicy } from "../../core/services/api/generated/model/policy";
export type { DnsPolicy };
export type { CheckedSnapshot, CheckedWarm };

/** object narrows untrusted JSON to a property-addressable object. */
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** integer checks that both JavaScript and the gateway can represent the quantity. */
function integer(
  value: unknown,
  min: number,
  max = Number.MAX_SAFE_INTEGER,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= min &&
    value <= max
  );
}

/** canonicalDomain returns a canonical exact ASCII DNS name, or null for invalid input. */
export function canonicalDomain(input: string): string | null {
  const trimmed = input.trim();
  if (!/^[A-Za-z0-9.-]+$/u.test(trimmed)) return null;
  const name = trimmed.toLowerCase().replace(/\.$/u, "");
  if (
    !name ||
    name.length > 253 ||
    (name.split(".").length === 4 &&
      name
        .split(".")
        .every(
          (part) => /^(?:0|[1-9]\d{0,2})$/u.test(part) && Number(part) <= 255,
        ))
  )
    return null;
  return name
    .split(".")
    .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
    ? name
    : null;
}

/** validSettings checks quantity bounds and the conditional emergency retention window. */
export function validSettings(v: unknown): v is DnsSettings {
  return (
    object(v) &&
    integer(v["retentionSeconds"], 0, 31536000) &&
    typeof v["serveStale"] === "boolean" &&
    integer(v["staleWindowSeconds"], 0, 31536000) &&
    (!v["serveStale"] ||
      (v["staleWindowSeconds"] > 0 &&
        v["staleWindowSeconds"] <= v["retentionSeconds"])) &&
    typeof v["automaticEnabled"] === "boolean" &&
    integer(v["threshold"], 1, 1000000) &&
    integer(v["windowHours"], 1, 8760) &&
    integer(v["intervalMinutes"], 1, 525600)
  );
}

/** names checks that a bounded list contains unique canonical domains. */
function names(v: unknown): v is string[] {
  return (
    Array.isArray(v) &&
    v.length <= 4096 &&
    v.every(
      (name) => typeof name === "string" && canonicalDomain(name) === name,
    ) &&
    new Set(v).size === v.length
  );
}

/** validSnapshot checks both policy lists, revision and settings before exposing any gateway values. */
export function validSnapshot(v: unknown): v is CheckedSnapshot {
  return (
    object(v) &&
    integer(v["revision"], 0) &&
    object(v["policy"]) &&
    validSettings(v["policy"]["settings"]) &&
    names(v["policy"]["manual"]) &&
    names(v["policy"]["exclusions"])
  );
}

/** validClientUdp checks the optional router-side attempt counters published by newer workers. */
function validClientUdp(v: unknown): boolean {
  return (
    v === undefined ||
    (object(v) &&
      integer(v["attempts"], 0) &&
      integer(v["unclassifiedAttempts"], 0, v["attempts"]) &&
      integer(v["retriedAttempts"], 0) &&
      (v["retriedAttempts"] === 0 ||
        v["retriedAttempts"] < v["attempts"] - v["unclassifiedAttempts"]))
  );
}

/** validWarm checks that observation rows identify unique domains and actual client counts. */
export function validWarm(v: unknown): v is CheckedWarm {
  if (
    !object(v) ||
    !integer(v["policyRevision"], 0) ||
    !validClientUdp(v["clientUdp"]) ||
    typeof v["observedAt"] !== "string" ||
    !Number.isFinite(Date.parse(v["observedAt"])) ||
    !Array.isArray(v["automatic"]) ||
    v["automatic"].length > 32768
  )
    return false;
  const seen = new Set<string>();
  for (const row of v["automatic"]) {
    if (
      !object(row) ||
      typeof row["domain"] !== "string" ||
      canonicalDomain(row["domain"]) !== row["domain"] ||
      seen.has(row["domain"]) ||
      !integer(row["clientRequests"], 1)
    )
      return false;
    seen.add(row["domain"]);
  }
  return true;
}

/** samePolicy compares all settings and both unordered sets in a validated acknowledgement. */
export function samePolicy(actual: DnsPolicy, desired: DnsPolicy): boolean {
  return (
    Object.entries(desired.settings).every(([key, value]) =>
      Object.entries(actual.settings).some(
        ([other, setting]) => key === other && value === setting,
      ),
    ) &&
    (["manual", "exclusions"] as const).every((list) => {
      const names = new Set(actual[list]);
      return (
        names.size === desired[list].length &&
        desired[list].every((name) => names.has(name))
      );
    })
  );
}
