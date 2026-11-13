import type { TrafficEvent } from "../services/api/generated/model/trafficEvent";

/** trafficOutcomeName reports the selected connector or an explicit block/unknown decision. */
export function trafficOutcomeName(
  event: TrafficEvent,
  resolveName: (id: string) => string,
): string {
  if (event.kind === "blocked") return "Заблокировано";
  return event.connection ? resolveName(event.connection) : "Не определено";
}
