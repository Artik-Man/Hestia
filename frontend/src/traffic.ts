import { ChangeDetectionStrategy, Component, signal } from "@angular/core";
import { FormControl, ReactiveFormsModule, Validators } from "@angular/forms";
import { toSignal } from "@angular/core/rxjs-interop";
import { TrafficEvents } from "./traffic-events";
import type { FlowProtocol } from "./traffic-observations";

/** TrafficScreen owns local search conditions and a retention draft while the journal source is unavailable. */
@Component({
  selector: "hestia-traffic",
  imports: [ReactiveFormsModule, TrafficEvents],
  templateUrl: "./traffic.html",
  styleUrl: "./traffic-quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TrafficScreen {
  protected readonly queryControl = new FormControl("", { nonNullable: true });
  protected readonly protocolControl = new FormControl<FlowProtocol | "">("", {
    nonNullable: true,
  });
  protected readonly periodControl = new FormControl(24, { nonNullable: true });
  protected readonly query = toSignal(this.queryControl.valueChanges, {
    initialValue: "",
  });
  protected readonly protocol = toSignal(this.protocolControl.valueChanges, {
    initialValue: this.protocolControl.value,
  });
  protected readonly period = toSignal(this.periodControl.valueChanges, {
    initialValue: 24,
  });
  protected readonly periods = [1, 6, 24, 72] as const;
  protected readonly retention = new FormControl<number | null>(24, [
    Validators.required,
    Validators.min(1),
    Validators.pattern(/^\d+$/),
  ]);
  protected readonly editRetention = signal(false);

  /** resetFilters restores the display window, empty search and all transport protocols. */
  protected resetFilters(): void {
    this.queryControl.reset();
    this.protocolControl.reset();
    this.periodControl.reset();
  }
}
