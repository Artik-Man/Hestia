import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  output,
  signal,
} from "@angular/core";
import {
  FormControl,
  FormGroup,
  ReactiveFormsModule,
  Validators,
} from "@angular/forms";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { HttpErrorResponse } from "@angular/common/http";
import type { TrafficSettings } from "../../services/api/generated/model/trafficSettings";
import { timeout } from "rxjs";
import { Toast } from "primeng/toast";
import { ButtonDirective } from "primeng/button";
import { DialogModule } from "primeng/dialog";
import { InputText } from "primeng/inputtext";
import { Notifications } from "../../services/notifications.service";
import { PanelService } from "../../services/api/generated/api/panel.service";
import {
  trafficLimits,
  validTrafficSettings,
} from "../../../routes/traffic/traffic-observations";

/** TrafficSettingsDialog reads effective limits on open and closes only after cancellation or a confirmed save. */
@Component({
  selector: "hestia-traffic-settings",
  imports: [
    Toast,
    ButtonDirective,
    DialogModule,
    InputText,
    ReactiveFormsModule,
  ],
  templateUrl: "./traffic-settings.component.html",
  styleUrl: "../../../styles/traffic-quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TrafficSettingsDialog {
  private readonly api = inject(PanelService);
  private readonly notifications = inject(Notifications);
  private readonly destroyRef = inject(DestroyRef);
  readonly closed = output<void>();
  readonly saved = output<void>();
  protected readonly expected = signal<TrafficSettings | null>(null);
  protected readonly saving = signal(false);
  protected readonly needsReload = signal(false);
  protected readonly limits = trafficLimits;
  protected readonly form = new FormGroup({
    maxMB: new FormControl(1024, {
      nonNullable: true,
      validators: [
        Validators.required,
        Validators.min(1),
        Validators.max(trafficLimits.maxMB),
        Validators.pattern(/^\d+$/),
      ],
    }),
    retentionHours: new FormControl(24, {
      nonNullable: true,
      validators: [
        Validators.required,
        Validators.min(1),
        Validators.max(trafficLimits.retentionHours),
        Validators.pattern(/^\d+$/),
      ],
    }),
  });

  /** Reads gateway settings before enabling writes, and cancels the read on navigation. */
  constructor() {
    this.reload();
  }

  /** reload replaces the draft and write precondition with the effective settings read from the gateway. */
  protected reload(): void {
    this.needsReload.set(false);
    this.expected.set(null);
    this.api
      .getTrafficSettings()
      .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (value: unknown) => {
          if (validTrafficSettings(value)) {
            this.form.reset(value);
            this.expected.set(this.form.getRawValue());
          } else
            this.requireReload("Шлюз вернул некорректные настройки журнала.");
        },
        error: () =>
          this.requireReload("Не удалось прочитать настройки журнала."),
      });
  }

  /** save submits both valid limits together and keeps the draft available after a failed write. */
  protected save(): void {
    const expected = this.expected();
    if (!expected || this.form.invalid || this.saving()) return;
    this.saving.set(true);
    const requested = this.form.getRawValue();
    this.api
      .updateTrafficSettings({ expected, proposed: requested })
      .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result: unknown) => {
          this.saving.set(false);
          if (
            !validTrafficSettings(result) ||
            result.maxMB !== requested.maxMB ||
            result.retentionHours !== requested.retentionHours
          ) {
            this.notifications.show(
              "error",
              "Шлюз не подтвердил настройки журнала.",
              "traffic-settings",
            );
            return;
          }
          this.notifications.show("success", "Настройки журнала сохранены.");
          this.saved.emit();
        },
        error: (failure: unknown) => {
          this.saving.set(false);
          if (failure instanceof HttpErrorResponse && failure.status === 409) {
            this.requireReload(
              "Настройки изменились на шлюзе. Загрузите актуальные значения и проверьте лимиты перед сохранением.",
              "warn",
            );
            return;
          }
          this.notifications.show(
            "error",
            "Не удалось сохранить настройки журнала.",
            "traffic-settings",
          );
        },
      });
  }

  /** requireReload disables stale writes and leaves the dialog ready to fetch current settings. */
  private requireReload(
    message: string,
    severity: "error" | "warn" = "error",
  ): void {
    this.expected.set(null);
    this.needsReload.set(true);
    this.notifications.show(severity, message, "traffic-settings");
  }
}
