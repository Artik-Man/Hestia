/** A completed probe records either an observed result or a local measurement failure. */
export interface ProbeObservation {
  readonly time: string;
  readonly group: string;
  readonly exit: string;
  readonly target: string;
  readonly protocol: "TCP" | "UDP" | "ICMP";
  readonly outcome: "reply" | "timeout" | "local-error";
  readonly latencyMs: number | null;
}

/** Switching records identify the affected scope, old/new exits and measured rationale. */
export interface SwitchObservation {
  readonly time: string;
  readonly group: string;
  readonly from: string;
  readonly to: string;
  readonly reason: string;
  readonly scope:
    | { kind: "group" }
    | {
        kind: "target";
        target: string;
        protocol: ProbeObservation["protocol"];
      };
}

/** ProbeTotals distinguishes local failures from packet loss and unknown latency from zero. */
export interface ProbeTotals {
  readonly samples: number;
  readonly timeouts: number;
  readonly localErrors: number;
  readonly meanLatencyMs: number | null;
}

/** summarizeProbes compares probes per exit within one group, target, protocol and time window. */
export function summarizeProbes(
  reports: readonly ProbeObservation[],
  group: string,
  target: string,
  protocol: ProbeObservation["protocol"],
  cutoff: number,
  end: number,
): ReadonlyMap<string, ProbeTotals> {
  const totals = new Map<
    string,
    {
      samples: number;
      timeouts: number;
      localErrors: number;
      latencySum: number;
      latencyCount: number;
    }
  >();
  for (const report of reports) {
    const time = Date.parse(report.time);
    if (
      report.group !== group ||
      report.target !== target ||
      report.protocol !== protocol ||
      !(time >= cutoff && time <= end)
    )
      continue;
    const total = totals.get(report.exit) ?? {
      samples: 0,
      timeouts: 0,
      localErrors: 0,
      latencySum: 0,
      latencyCount: 0,
    };
    if (report.outcome === "local-error") total.localErrors++;
    else {
      total.samples++;
      if (report.outcome === "timeout") total.timeouts++;
      else if (report.latencyMs !== null) {
        total.latencySum += report.latencyMs;
        total.latencyCount++;
      }
    }
    totals.set(report.exit, total);
  }
  return new Map(
    Array.from(totals, ([exit, t]) => [
      exit,
      {
        samples: t.samples,
        timeouts: t.timeouts,
        localErrors: t.localErrors,
        meanLatencyMs: t.latencyCount ? t.latencySum / t.latencyCount : null,
      },
    ]),
  );
}
