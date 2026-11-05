import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  signal,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormControl, ReactiveFormsModule } from "@angular/forms";
import { ButtonDirective } from "primeng/button";
import { InputText } from "primeng/inputtext";
import { timeout } from "rxjs";
import { PanelService } from "../../services/api/generated/api/panel.service";

/** GeoipSettings edits a write-only 2ip credential independently of DNS cache policy. */
@Component({
  selector: "hestia-geoip-settings",
  imports: [ButtonDirective, InputText, ReactiveFormsModule],
  templateUrl: "./geoip-settings.component.html",
  styleUrl: "../../../styles/dns.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GeoipSettings {
  private readonly api = inject(PanelService);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly token = new FormControl("", { nonNullable: true });
  protected readonly configured = signal<boolean | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal("");
  protected readonly replaced = signal(false);

  /** Reads only whether the gateway has a credential when the settings open. */
  constructor() {
    this.read();
  }

  /** read refreshes confirmed state without exposing saved key material. */
  protected read(): void {
    this.submit();
  }

  /** save submits a replacement key or an explicit removal, then clears the secret input. */
  protected save(remove = false): void {
    if (this.configured() === null) return;
    const token = remove ? "" : this.token.value.trim();
    if (!remove && !token) return;
    this.submit(token);
  }

  /** submit serializes requests and requires a fresh read after an ambiguous write failure. */
  private submit(token?: string): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set("");
    this.replaced.set(false);
    const expected = token === undefined ? undefined : Boolean(token);
    const request =
      token === undefined
        ? this.api.getDnsGeoip()
        : this.api.updateDnsGeoip({ token });
    this.token.reset();
    request
      .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (body: unknown) => {
          this.busy.set(false);
          if (
            typeof body === "object" &&
            body !== null &&
            "configured" in body &&
            typeof body.configured === "boolean" &&
            (expected === undefined || body.configured === expected)
          ) {
            this.replaced.set(expected === true && this.configured() === true);
            this.configured.set(body.configured);
          } else {
            this.failed();
          }
        },
        error: (error: unknown) => {
          this.busy.set(false);
          if (
            expected !== undefined &&
            error instanceof HttpErrorResponse &&
            [400, 413, 422].includes(error.status)
          ) {
            this.error.set(
              "Шлюз отклонил ключ. Проверьте значение и повторите сохранение.",
            );
            return;
          }
          this.failed();
        },
      });
  }

  /** failed hides stale key state until the operator reloads it. */
  private failed(): void {
    this.configured.set(null);
    this.error.set(
      "Не удалось подтвердить состояние ключа на шлюзе. Перечитайте настройки.",
    );
  }
}
