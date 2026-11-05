import type { QualityReport } from "../../core/services/api/generated/model/qualityReport";
import type { QualitySettings } from "../../core/services/api/generated/model/qualitySettings";

export const qualityProtocols = [
  "UDP",
  "TCP",
  "ICMP",
  "DNS",
  "HTTPS",
  "HTTP3",
] as const;

/** qualityLabel renders the protocol name used on check cards and result columns. */
export function qualityLabel(protocol: Check["protocol"]): string {
  return protocol === "HTTP3" ? "HTTP/3" : protocol;
}

/** validProtocol identifies a supported quality probe at the network boundary. */
function validProtocol(value: unknown): value is Check["protocol"] {
  return qualityProtocols.some((p) => p === value);
}

type Check = QualitySettings["checks"][number];
type Connection = QualityReport["groups"][number]["connections"][number];
type Result = Connection["result"]["checks"][number];

/** record exposes only properties of a JSON object. */
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** whole checks bounded integer settings and nonnegative counters. */
function whole(
  value: unknown,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= min &&
    value <= max
  );
}

/** validTarget requires a literal IP and explicit service port, including brackets for IPv6. */
function validTarget(target: unknown, dns: boolean): boolean {
  if (typeof target !== "string") return false;
  const match = /^(\[[0-9a-fA-F:.]+\]|[0-9.]+):(\d+)$/.exec(target);
  return (
    !!match &&
    validLiteral(match[1]) &&
    whole(Number(match[2]), 1, 65535) &&
    (!dns || Number(match[2]) === 53)
  );
}

/** validLiteral rejects ambiguous IPv4 spellings and malformed bracketed IPv6 addresses. */
function validLiteral(text: string): boolean {
  if (!text.startsWith("["))
    return (
      /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u.test(text) &&
      text.split(".").every((part) => Number(part) <= 255)
    );
  try {
    return new URL("http://" + text).hostname.startsWith("[");
  } catch {
    return false;
  }
}

/** validDomain allows an absolute or relative ASCII DNS query name, including numeric labels. */
function validDomain(text: string): boolean {
  return (
    text.length <= 253 &&
    text
      .replace(/\.$/u, "")
      .split(".")
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(label))
  );
}

/** validCheck checks saved settings, or allows raw TCP target strings in a save request for server-side normalization. */
export function validCheck(value: unknown, tcpInput = false): value is Check {
  if (!record(value) || !validProtocol(value.protocol)) return false;
  const dns = value.protocol === "UDP" || value.protocol === "DNS";
  const http = value.protocol === "HTTPS" || value.protocol === "HTTP3";
  return (
    whole(value.intervalSeconds, 1, 3600) &&
    whole(value.timeoutSeconds, 1, Math.min(value.intervalSeconds, 30)) &&
    Array.isArray(value.targets) &&
    value.targets.length >= 1 &&
    value.targets.length <= 8 &&
    (value.protocol !== "UDP" || value.targets.length === 2) &&
    new Set(value.targets).size === value.targets.length &&
    value.targets.every((target) =>
      value.protocol === "ICMP"
        ? typeof target === "string" &&
          validLiteral(target.includes(":") ? "[" + target + "]" : target)
        : tcpInput && value.protocol === "TCP"
          ? typeof target === "string" && !!target.trim()
          : validTarget(target, dns),
    ) &&
    (http
      ? typeof value.serverName === "string" &&
        validDomain(value.serverName) &&
        !validLiteral(value.serverName) &&
        !value.serverName.endsWith(".") &&
        typeof value.requestPath === "string" &&
        value.requestPath.length <= 1024 &&
        /^\/(?!\/)[^\s#\\]*$/u.test(value.requestPath)
      : !value.serverName && !value.requestPath) &&
    (dns
      ? typeof value.dnsName === "string" && validDomain(value.dnsName)
      : !value.dnsName)
  );
}

/** isQualitySettings verifies the full editable settings contract with at most one check per supported protocol. */
export function isQualitySettings(value: unknown): value is QualitySettings {
  return (
    record(value) &&
    whole(value.windowMinutes, 1, 1440) &&
    Array.isArray(value.checks) &&
    value.checks.length <= qualityProtocols.length &&
    value.checks.every((check) => validCheck(check)) &&
    new Set(value.checks.map((c) => c.protocol)).size === value.checks.length
  );
}

/** sameQualityCheck compares one persisted check's configuration, preserving target order. */
export function sameQualityCheck(check: Check, other: Check): boolean {
  return (
    check.protocol === other.protocol &&
    check.intervalSeconds === other.intervalSeconds &&
    check.timeoutSeconds === other.timeoutSeconds &&
    (check.dnsName ?? "") === (other.dnsName ?? "") &&
    (check.serverName ?? "") === (other.serverName ?? "") &&
    (check.requestPath ?? "") === (other.requestPath ?? "") &&
    check.targets.length === other.targets.length &&
    check.targets.every((target, i) => target === other.targets[i])
  );
}

/** score accepts bounded finite scores or an explicit missing sample indicator. */
function score(value: unknown): boolean {
  return (
    value === null ||
    (typeof value === "number" &&
      Number.isFinite(value) &&
      value >= 0 &&
      value <= 100)
  );
}

/** counts checks sample/success relationships and local errors on a result or target. */
function counts(value: Record<string, unknown>): boolean {
  return (
    whole(value.samples) &&
    whole(value.successes, 0, value.samples) &&
    whole(value.localErrors)
  );
}

/** validResponseCodes accepts an optional breakdown of DNS errors by their nonzero decimal RCODE. */
function validResponseCodes(value: unknown, errors: number): boolean {
  if (value === undefined) return true;
  if (!record(value)) return false;
  let total = 0;
  for (const [key, count] of Object.entries(value)) {
    if (
      !/^[1-9]\d{0,3}$/u.test(key) ||
      Number(key) > 4095 ||
      !whole(count, 1, errors)
    )
      return false;
    total += count;
  }
  return total === errors;
}

/** validResult checks each target and distinguishes unsupported checks, missing samples and measured scores. */
function validResult(value: unknown): value is Result {
  return (
    record(value) &&
    validProtocol(value.protocol) &&
    counts(value) &&
    score(value.score) &&
    (value.score === null) === (value.samples === 0) &&
    Array.isArray(value.targets) &&
    (value.unsupported === undefined ||
      typeof value.unsupported === "boolean") &&
    (!value.unsupported ||
      (value.protocol === "ICMP" &&
        value.samples === 0 &&
        value.localErrors === 0 &&
        value.targets.length === 0)) &&
    value.targets.every(
      (t) =>
        record(t) &&
        typeof t.target === "string" &&
        counts(t) &&
        whole(t.dnsErrors) &&
        validResponseCodes(t.dnsResponseCodes, t.dnsErrors) &&
        score(t.score) &&
        (t.score === null) === (t.samples === 0),
    )
  );
}

/** validConnection checks completeness of per-protocol results before group rows can be rendered. */
function validConnection(value: unknown): value is Connection {
  return (
    record(value) &&
    typeof value.id === "string" &&
    !!value.id &&
    typeof value.available === "boolean" &&
    typeof value.active === "boolean" &&
    record(value.result) &&
    score(value.result.overall) &&
    Array.isArray(value.result.checks) &&
    value.result.checks.every(validResult) &&
    new Set(value.result.checks.map((c) => c.protocol)).size ===
      value.result.checks.length
  );
}

/** isQualityReport validates the network payload without reordering the controller's group rows. */
export function isQualityReport(value: unknown): value is QualityReport {
  return (
    record(value) &&
    isQualitySettings(value.settings) &&
    typeof value.capturedAt === "string" &&
    (!value.capturedAt || Number.isFinite(Date.parse(value.capturedAt))) &&
    Array.isArray(value.groups) &&
    value.groups.every(
      (group) =>
        record(group) &&
        typeof group.id === "string" &&
        typeof group.name === "string" &&
        Array.isArray(group.connections) &&
        group.connections.every(validConnection),
    )
  );
}
