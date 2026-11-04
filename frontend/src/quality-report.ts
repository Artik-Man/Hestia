import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  signal,
} from "@angular/core";
import { RouterLink } from "@angular/router";
import { FormControl, ReactiveFormsModule, Validators } from "@angular/forms";
import { toSignal } from "@angular/core/rxjs-interop";
import type { Group } from "./api/generated/model/group";
import {
  summarizeProbes,
  type ProbeObservation,
  type SwitchObservation,
} from "./quality-observations";

/** A report's capture time fixes a reproducible comparison window for all channels. */
interface QualityReport {
  readonly capturedAt: number;
  readonly probes: readonly ProbeObservation[];
  readonly switches: readonly SwitchObservation[];
}

/** QualityComparison combines known topology with separately supplied measurements and switch history. */
@Component({
  selector: "hestia-quality-comparison",
  imports: [ReactiveFormsModule, RouterLink],
  templateUrl: "./quality-report.html",
  styleUrl: "./traffic-quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class QualityComparison {
  readonly groups = input.required<readonly Group[]>();
  readonly report = input.required<QualityReport | null>();
  protected readonly selectedGroup = signal("");
  protected readonly selectedTarget = signal("");
  protected readonly protocol = new FormControl<ProbeObservation["protocol"]>(
    "UDP",
    { nonNullable: true },
  );
  protected readonly minutes = new FormControl<number | null>(60, [
    Validators.required,
    Validators.min(1),
    Validators.pattern(/^\d+$/),
  ]);
  private readonly selectedProtocol = toSignal(this.protocol.valueChanges, {
    initialValue: this.protocol.value,
  });
  private readonly interval = toSignal(this.minutes.valueChanges, {
    initialValue: this.minutes.value,
  });
  protected readonly group = computed(
    () =>
      this.groups().find((group) => group.id === this.selectedGroup()) ??
      this.groups().at(0),
  );
  protected readonly targets = computed(() => {
    const report = this.report();
    if (!report) return [];
    const group = this.group()?.id;
    return [
      ...new Set([
        ...report.probes
          .filter(
            (p) => p.group === group && p.protocol === this.selectedProtocol(),
          )
          .map((p) => p.target),
        ...report.switches
          .filter((s) => s.group === group)
          .flatMap((s) =>
            s.scope.kind === "target" &&
            s.scope.protocol === this.selectedProtocol()
              ? [s.scope.target]
              : [],
          ),
      ]),
    ].sort();
  });
  protected readonly target = computed(() =>
    this.targets().includes(this.selectedTarget())
      ? this.selectedTarget()
      : (this.targets()[0] ?? ""),
  );
  private readonly range = computed(() => {
    const minutes = this.interval();
    const report = this.report();
    if (
      !report ||
      minutes === null ||
      !Number.isSafeInteger(minutes) ||
      minutes < 1
    )
      return null;
    return {
      start: report.capturedAt - minutes * 60_000,
      end: report.capturedAt,
    };
  });
  protected readonly totals = computed(() => {
    const range = this.range();
    const report = this.report();
    const group = this.group();
    if (!range || !report || !group) return null;
    return summarizeProbes(
      report.probes,
      group.id,
      this.target(),
      this.selectedProtocol(),
      range.start,
      range.end,
    );
  });
  protected readonly switches = computed(() => {
    const range = this.range();
    const report = this.report();
    if (!range || !report) return null;
    return report.switches.filter((event) => {
      const time = Date.parse(event.time);
      return (
        event.group === this.group()?.id &&
        time >= range.start &&
        time <= range.end &&
        (event.scope.kind === "group" ||
          (event.scope.target === this.target() &&
            event.scope.protocol === this.selectedProtocol()))
      );
    });
  });
}
