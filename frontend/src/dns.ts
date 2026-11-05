import { Notifications } from "./notifications";
import {
  ChangeDetectionStrategy,
  Component,
  Injectable,
  inject,
  signal,
} from "@angular/core";
import { FormControl, FormGroup, ReactiveFormsModule } from "@angular/forms";
import { DnsNames } from "./dns-names";

/** Numeric drafts use blank controls until the operator enters values; no live values are assumed. */
interface DnsDraft {
  retention: number | null;
  stale: boolean;
  staleAge: number | null;
  warm: boolean;
  threshold: number | null;
  window: number | null;
  interval: number | null;
}

/** draftErrors validates only the settings enabled by the operator, in the displayed units. */
function draftErrors(value: DnsDraft): string[] {
  const errors: string[] = [];
  if (!whole(value.retention, 0))
    errors.push(
      "Укажите целое число секунд хранения после TTL, не меньше нуля.",
    );
  if (value.stale) {
    if (!whole(value.staleAge, 1))
      errors.push("Для выдачи при сбое укажите положительное окно в секундах.");
    else if (value.retention !== null && value.staleAge > value.retention)
      errors.push("Окно выдачи не может превышать срок хранения после TTL.");
  }
  if (value.warm) {
    if (!whole(value.threshold, 1))
      errors.push("Порог обращений должен быть положительным целым числом.");
    if (!whole(value.window, 1))
      errors.push(
        "Окно активности должно быть положительным целым числом часов.",
      );
    if (!whole(value.interval, 1))
      errors.push(
        "Интервал обновления должен быть положительным целым числом минут.",
      );
  }
  return errors;
}

/** whole checks whether an entered quantity is a safe integer at or above its minimum. */
function whole(value: number | null, minimum: number): value is number {
  return value !== null && Number.isSafeInteger(value) && value >= minimum;
}

/** DnsDraftState retains only proposed settings in memory until the panel is reloaded. */
@Injectable({ providedIn: "root" })
class DnsDraftState {
  readonly form = new FormGroup({
    retention: new FormControl<number | null>(null),
    stale: new FormControl(false, { nonNullable: true }),
    staleAge: new FormControl<number | null>(null),
    warm: new FormControl(false, { nonNullable: true }),
    threshold: new FormControl<number | null>(null),
    window: new FormControl<number | null>(null),
    interval: new FormControl<number | null>(null),
  });
}

/** DnsScreen lets an operator validate a cache and warm-up draft without changing gateway settings. */
@Component({
  selector: "hestia-dns",
  imports: [ReactiveFormsModule, DnsNames],
  templateUrl: "./dns.html",
  styleUrl: "./dns.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DnsScreen {
  private readonly notifications = inject(Notifications);
  protected readonly form = inject(DnsDraftState).form;
  protected readonly errors = signal<readonly string[]>([]);

  /** validate checks enabled sections and reports their validity without submitting anything. */
  protected validate(): void {
    this.errors.set(draftErrors(this.form.getRawValue()));
    if (!this.errors().length) {
      this.notifications.show(
        "success",
        "Черновик DNS проверен. Параметры согласованы между собой. Изменения не отправлены на шлюз.",
      );
    }
  }

  /** clearCheck removes the prior result when the proposed settings change. */
  protected clearCheck(): void {
    this.errors.set([]);
  }

  /** reset discards the proposed settings and returns the form to its initial blank state. */
  protected reset(): void {
    this.form.reset();
    this.clearCheck();
  }
}
