import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  signal,
  viewChild,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormControl, FormGroup, ReactiveFormsModule } from "@angular/forms";
import { ButtonDirective } from "primeng/button";
import { InputNumber } from "primeng/inputnumber";
import { ToggleSwitch } from "primeng/toggleswitch";
import { Message } from "primeng/message";
import { Subscription, timer, timeout } from "rxjs";
import { PanelService } from "../../core/services/api/generated/api/panel.service";
import {
  DnsNames,
  type NamesEdit,
} from "../../core/components/dns-names/dns-names.component";
import {
  samePolicy,
  validSettings,
  validSnapshot,
  validWarm,
  type DnsPolicy,
  type CheckedSnapshot,
  type CheckedWarm,
} from "./dns-validation";

/** DnsScreen edits gateway-confirmed policy and displays separately versioned warm observations. */
@Component({
  selector: "hestia-dns",
  imports: [
    ReactiveFormsModule,
    ButtonDirective,
    InputNumber,
    ToggleSwitch,
    Message,
    DnsNames,
  ],
  templateUrl: "./dns.component.html",
  styleUrl: "../../styles/dns.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DnsScreen {
  private readonly api = inject(PanelService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly lists = viewChild(DnsNames);
  protected readonly snapshot = signal<CheckedSnapshot | null>(null);
  protected readonly report = signal<CheckedWarm | null>(null);
  protected readonly observationState = signal<
    "loading" | "ready" | "unavailable"
  >("loading");
  protected readonly reading = signal(false);
  protected readonly saving = signal(false);
  protected readonly needsReload = signal(false);
  protected readonly error = signal("");
  protected readonly success = signal("");
  private warmRequest?: Subscription;

  protected readonly form = new FormGroup({
    retentionSeconds: new FormControl<number | null>(null),
    serveStale: new FormControl(false, { nonNullable: true }),
    staleWindowSeconds: new FormControl<number | null>(null),
    automaticEnabled: new FormControl(false, { nonNullable: true }),
    threshold: new FormControl<number | null>(null),
    windowHours: new FormControl<number | null>(null),
    intervalMinutes: new FormControl<number | null>(null),
  });

  /** Loads policy and periodically reads authoritative telemetry while the route is mounted. */
  constructor() {
    this.loadPolicy();
    timer(0, 15000)
      .pipe(takeUntilDestroyed())
      .subscribe(() => this.loadWarm());
  }

  /** loadPolicy replaces the editor with a fresh authoritative version after initial load or explicit reload. */
  protected loadPolicy(): void {
    if (this.reading() || this.saving()) return;
    this.reading.set(true);
    this.error.set("");
    this.success.set("");
    this.api
      .getDnsPolicy()
      .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (body: unknown) => {
          this.reading.set(false);
          if (!validSnapshot(body)) {
            this.readFailure();
            return;
          }
          this.snapshot.set(body);
          this.form.reset(body.policy.settings);
          this.needsReload.set(false);
          this.loadWarm();
        },
        error: () => {
          this.reading.set(false);
          this.readFailure();
        },
      });
  }

  /** readFailure prevents writes from stale or unknown policy until a valid read succeeds. */
  private readFailure(): void {
    this.needsReload.set(true);
    this.error.set(
      "Не удалось прочитать действующие настройки DNS. Повторите загрузку.",
    );
  }

  /** loadWarm refreshes observations independently of edits and distinguishes unavailable from empty. */
  private loadWarm(): void {
    this.warmRequest?.unsubscribe();
    this.warmRequest = this.api
      .getDnsWarm()
      .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (body: unknown) => {
          if (validWarm(body)) {
            this.report.set(body);
            this.observationState.set("ready");
          } else this.observationState.set("unavailable");
        },
        error: () => this.observationState.set("unavailable"),
      });
  }

  /** saveSettings validates visible quantity ranges before submitting the settings change. */
  protected saveSettings(): void {
    const snapshot = this.snapshot(),
      settings = this.form.getRawValue();
    if (!snapshot) return;
    if (!validSettings(settings)) {
      this.success.set("");
      this.error.set(
        "Проверьте границы чисел. Окно выдачи при сбое должно быть положительным и укладываться в срок хранения.",
      );
      return;
    }
    this.save({ ...snapshot.policy, settings });
  }

  /** changeList updates only the targeted list using confirmed settings rather than the form's unsaved draft. */
  protected changeList(edit: NamesEdit): void {
    const snapshot = this.snapshot();
    if (snapshot)
      this.save({ ...snapshot.policy, [edit.list]: edit.names }, edit);
  }

  /** save serializes writes, checks the acknowledgement, and requires a reread after ambiguous outcomes or conflicts. */
  private save(policy: DnsPolicy, edit?: NamesEdit): void {
    const snapshot = this.snapshot();
    if (!snapshot || this.saving() || this.reading() || this.needsReload())
      return;
    this.saving.set(true);
    this.error.set("");
    this.success.set("");
    this.api
      .updateDnsPolicy({ expectedRevision: snapshot.revision, policy })
      .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (body: unknown) => {
          this.saving.set(false);
          if (
            !validSnapshot(body) ||
            !samePolicy(body.policy, policy) ||
            body.revision !==
              snapshot.revision +
                (snapshot.revision > 0 && samePolicy(snapshot.policy, policy)
                  ? 0
                  : 1)
          ) {
            this.needsReload.set(true);
            this.error.set(
              "Ответ шлюза не подтверждает изменение. Перечитайте настройки DNS.",
            );
            return;
          }
          this.snapshot.set(body);
          if (!edit) this.form.reset(body.policy.settings);
          else if (edit.resetEditor) this.lists()?.clearEditor(edit.list);
          this.success.set(
            edit ? "Список сохранён." : "Настройки DNS сохранены.",
          );
          this.loadWarm();
        },
        error: (error: unknown) => {
          this.saving.set(false);
          const status = error instanceof HttpErrorResponse ? error.status : 0;
          this.needsReload.set(![400, 403, 413, 422].includes(status));
          this.error.set(
            status === 409
              ? "Настройки изменились. Перечитайте значения со шлюза перед повторным изменением."
              : status === 403
                ? "Недостаточно прав для изменения DNS."
                : status === 422 || status === 400 || status === 413
                  ? "Шлюз отклонил параметры DNS. Проверьте введённые значения."
                  : "Сохранение не подтверждено. Перечитайте настройки DNS.",
          );
        },
      });
  }
}
