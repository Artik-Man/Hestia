import type { TrafficEvent } from "../../core/services/api/generated/model/trafficEvent";
import type { TrafficPage } from "../../core/services/api/generated/model/trafficPage";
import type { TrafficSettings } from "../../core/services/api/generated/model/trafficSettings";

/** Shared gateway bounds for retention settings, query pages and the client-side event cache. */
export const trafficLimits = {
  maxMB: 1048576,
  retentionHours: 87600,
  page: 500,
} as const;

/** record rejects arrays and null before validating the gateway's JSON properties. */
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** integer checks a finite inclusive range before using a quantity in the UI. */
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

/** validTrafficSettings checks both independently configurable journal limits. */
export function validTrafficSettings(value: unknown): value is TrafficSettings {
  return (
    record(value) &&
    integer(value["maxMB"], 1, trafficLimits.maxMB) &&
    integer(value["retentionHours"], 1, trafficLimits.retentionHours)
  );
}

/** validEvent checks the timestamp, transport and result before displaying a gateway event. */
function validEvent(value: unknown): value is TrafficEvent {
  if (
    !record(value) ||
    typeof value["id"] !== "string" ||
    !value["id"] ||
    typeof value["time"] !== "string" ||
    !Number.isFinite(Date.parse(value["time"])) ||
    (value["protocol"] !== "TCP" && value["protocol"] !== "UDP") ||
    typeof value["address"] !== "string" ||
    !(value["address"] || value["domain"] || value["fakeIP"]) ||
    (value["country"] !== undefined &&
      (!value["address"] ||
        typeof value["country"] !== "string" ||
        !/^[A-Z]{2}$/u.test(value["country"]))) ||
    !integer(value["port"], 0, 65535)
  )
    return false;
  if (
    ![
      "domain",
      "fakeIP",
      "group",
      "reason",
      "connection",
      "namespace",
      "networkInterface",
      "dnsQueryId",
      "blockReason",
    ].every((key) => value[key] === undefined || typeof value[key] === "string")
  )
    return false;
  if (
    value["firstReplyMs"] !== undefined &&
    (typeof value["firstReplyMs"] !== "number" ||
      !Number.isFinite(value["firstReplyMs"]) ||
      value["firstReplyMs"] < 0)
  )
    return false;
  if (value["kind"] === "observed")
    return !!value["connection"] && !!value["networkInterface"];
  if (value["networkInterface"]) return false;
  return value["kind"] === "blocked"
    ? !!value["blockReason"]
    : value["kind"] === "unconfirmed";
}

/** validTrafficPage bounds a sparse viewport and checks that returned events fit the requested snapshot page. */
export function validTrafficPage(
  value: unknown,
  offset: number,
  limit: number,
  snapshot?: string,
): value is TrafficPage {
  return (
    record(value) &&
    integer(value["total"], 0, 0xffffffff) &&
    integer(value["lost"], 0) &&
    typeof value["sourceAvailable"] === "boolean" &&
    (value["lastInterruption"] === undefined ||
      (typeof value["lastInterruption"] === "string" &&
        Number.isFinite(Date.parse(value["lastInterruption"])))) &&
    typeof value["snapshot"] === "string" &&
    !!value["snapshot"] &&
    (!snapshot || value["snapshot"] === snapshot) &&
    Array.isArray(value["events"]) &&
    value["events"].length ===
      Math.min(limit, Math.max(0, value["total"] - offset)) &&
    value["events"].every(validEvent) &&
    Array.isArray(value["outputs"]) &&
    value["outputs"].every((id) => typeof id === "string" && id.length > 0)
  );
}
