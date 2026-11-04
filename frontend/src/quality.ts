import {
  ChangeDetectionStrategy,
  Component,
  inject,
  signal,
} from "@angular/core";
import { FormControl, ReactiveFormsModule, Validators } from "@angular/forms";
import { SnapshotState } from "./snapshot-state";
import { QualityComparison } from "./quality-report";

/** QualityScreen reads actual exit topology and presents unavailable telemetry separately. */
@Component({
  selector: "hestia-quality",
  imports: [QualityComparison, ReactiveFormsModule],
  templateUrl: "./quality.html",
  styleUrl: "./traffic-quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class QualityScreen {
  protected readonly state = inject(SnapshotState);
  protected readonly editWindow = signal(false);
  protected readonly controllerMinutes = new FormControl<number | null>(60, [
    Validators.required,
    Validators.min(1),
    Validators.pattern(/^\d+$/),
  ]);
}
