import type { Hysteria2Connection } from "../services/api/generated/model/hysteria2Connection";
import {
  isConnectionName,
  isConnectionUUID,
  isUnderlayOrder,
} from "./awg-connection";
import { normalizeHysteriaHost } from "./hysteria2-host";
/** isHysteria2Connection validates public profile data before the panel displays or edits it. */
export function isHysteria2Connection(
  value: unknown,
): value is Hysteria2Connection {
  if (!value || typeof value !== "object") return false;
  return (
    (!("enabled" in value) || typeof value.enabled === "boolean") &&
    "id" in value &&
    typeof value.id === "string" &&
    isConnectionUUID(value.id) &&
    "name" in value &&
    isConnectionName(value.name) &&
    "group" in value &&
    typeof value.group === "string" &&
    !!value.group &&
    "priority" in value &&
    typeof value.priority === "number" &&
    Number.isInteger(value.priority) &&
    value.priority >= 1 &&
    (!("underlay" in value) ||
      (typeof value.underlay === "string" && !!value.underlay)) &&
    (!("underlays" in value) || isUnderlayOrder(value.underlays, value.id)) &&
    (!("activeUnderlay" in value) ||
      (typeof value.activeUnderlay === "string" &&
        (("underlays" in value &&
          Array.isArray(value.underlays) &&
          value.underlays.includes(value.activeUnderlay)) ||
          ("underlay" in value && value.underlay === value.activeUnderlay)))) &&
    "server" in value &&
    typeof value.server === "string" &&
    normalizeHysteriaHost(value.server) === value.server &&
    "port" in value &&
    typeof value.port === "number" &&
    Number.isInteger(value.port) &&
    value.port >= 1 &&
    value.port <= 65535 &&
    (!("serverName" in value) ||
      (typeof value.serverName === "string" &&
        (!value.serverName ||
          normalizeHysteriaHost(value.serverName) === value.serverName))) &&
    (!("certificatePEM" in value) ||
      typeof value.certificatePEM === "string") &&
    !("password" in value)
  );
}
