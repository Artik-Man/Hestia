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
import { Notifications } from "../../services/notifications.service";
import { timeout } from "rxjs";
import { PanelService } from "../../services/api/generated/api/panel.service";

/** GeoipSettings displays and edits the saved 2ip credential independently of DNS cache policy. */
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
  protected readonly savedToken = signal("");
  protected readonly busy = signal(false);
  private readonly notifications = inject(Notifications);

  /** Loads the saved key when settings open. */
  constructor() {
    this.read();
  }

  /** read loads the confirmed key for display. */
  protected read(): void {
    this.submit();
  }

  /** save submits a replacement key or an explicit removal, and displays the confirmed value. */
  protected save(remove = false): void {
    if (this.configured() === null) return;
    const token = remove ? "" : this.token.value.trim();
    if (token === this.savedToken() || (!remove && !token)) return;
    this.submit(token);
  }

  /** submit serializes requests and requires a fresh read after an ambiguous write failure. */
  private submit(token?: string): void {
    if (this.busy()) return;
    this.busy.set(true);
    const request =
      token === undefined
        ? this.api.getDnsGeoip()
        : this.api.updateDnsGeoip({ token });
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
            "token" in body &&
            typeof body.token === "string" &&
            body.token.length <= 256 &&
            body.configured === Boolean(body.token) &&
            (token === undefined || body.token === token)
          ) {
            if (token !== undefined) {
              const message = !token
                ? "Ключ удалён."
                : this.configured()
                  ? "Ключ заменён."
                  : "Ключ сохранён.";
              this.notifications.show("success", message);
            }
            this.savedToken.set(body.token);
            this.token.reset(body.token);
            this.configured.set(body.configured);
          } else {
            this.failed();
          }
        },
        error: (error: unknown) => {
          this.busy.set(false);
          if (
            token !== undefined &&
            error instanceof HttpErrorResponse &&
            [400, 413, 422].includes(error.status)
          ) {
            this.notifications.show(
              "error",
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
    this.notifications.show(
      "error",
      "Не удалось подтвердить состояние ключа на шлюзе. Перечитайте настройки.",
    );
  }
}
