/** Client-side display types hold validated flow observations and are independent of wire transport. */
export type FlowProtocol = "TCP" | "UDP";

interface DNSAttempt {
  readonly resolver: string;
  readonly connection: string;
  readonly startedAt: string;
  readonly elapsedMs: number;
  readonly result: string;
  readonly group: string;
  readonly namespace: string;
  readonly networkInterface: string;
  readonly fromCache: boolean;
  readonly answers: readonly { address: string; ttlSeconds: number }[];
}

interface RelatedDNS {
  readonly queryId: string;
  readonly name: string;
  readonly recordType: string;
  readonly clientAddresses: readonly string[];
  readonly responseTimeMs: number;
  readonly attempts: readonly DNSAttempt[];
}

/** A blocked or unconfirmed flow cannot carry an observed interface. */
type FlowResult =
  | { kind: "blocked"; reason: string }
  | { kind: "unconfirmed" }
  | {
      kind: "observed";
      connection: string;
      namespace: string;
      networkInterface: string;
    };

export interface FlowEvent {
  readonly id: string;
  readonly time: string;
  readonly protocol: FlowProtocol;
  readonly domain: string | null;
  readonly address: string;
  readonly port: number;
  readonly fakeIP: string | null;
  readonly group: string;
  readonly reason: string;
  readonly firstReplyMs: number | null;
  readonly result: FlowResult;
  readonly dns: RelatedDNS | null;
}

/** filterFlows intersects a time window, case-insensitive destination substring and optional flow protocol. */
export function filterFlows(
  events: readonly FlowEvent[],
  query: string,
  protocol: FlowProtocol | "",
  hours: number,
  end: number,
): readonly FlowEvent[] {
  const search = query.trim().toLowerCase();
  const start = end - hours * 3_600_000;
  return events.filter((event) => {
    const time = Date.parse(event.time);
    return (
      time >= start &&
      time <= end &&
      (!protocol || event.protocol === protocol) &&
      [event.address, event.domain, event.fakeIP].some((value) =>
        value?.toLowerCase().includes(search),
      )
    );
  });
}
