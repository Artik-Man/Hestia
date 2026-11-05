import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  input,
  output,
  signal,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { HttpErrorResponse } from "@angular/common/http";
import { FormsModule } from "@angular/forms";
import { ButtonDirective } from "primeng/button";
import { InputText } from "primeng/inputtext";
import { Textarea } from "primeng/textarea";
import { timeout } from "rxjs";
import { PanelService } from "./api/generated/api/panel.service";
import type { QualitySettings } from "./api/generated/model/qualitySettings";
import { Notifications } from "./notifications";
import { isQualitySettings, sameQualitySettings } from "./quality-observations";

type Check = QualitySettings["checks"][number];

/** EditableSettings keeps the raw multiline target list intact while the operator is typing. */
interface EditableSettings {
  windowMinutes: number | null;
  checks: (Omit<Check, "targets" | "intervalSeconds" | "timeoutSeconds"> & {
    targets: string;
    intervalSeconds: number | null;
    timeoutSeconds: number | null;
  })[];
}

/** QualityEditor edits one complete settings document and confirms the gateway's validated response. */
@Component({
  selector: "hestia-quality-settings",
  imports: [FormsModule, ButtonDirective, InputText, Textarea],
  templateUrl: "./quality-report.html",
  styleUrl: "./quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class QualityEditor {
  readonly settings = input.required<QualitySettings>();
  readonly saved = output<void>();
  protected readonly draft = signal<EditableSettings | null>(null);
  protected readonly saving = signal(false);
  private readonly api = inject(PanelService);
  private readonly notices = inject(Notifications);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly protocols = ["UDP", "TCP"] as const;
  private original?: QualitySettings;

  /** edit snapshots all settings so periodic reads cannot overwrite an unsaved change. */
  protected edit(): void {
    const current = this.settings();
    this.original = current;
    this.draft.set({
      windowMinutes: current.windowMinutes,
      checks: current.checks.map((check) => ({
        ...check,
        targets: check.targets.join("\n"),
      })),
    });
  }

  /** hasCheck indicates which protocols can still be added to the current draft. */
  protected hasCheck(
    form: EditableSettings,
    protocol: Check["protocol"],
  ): boolean {
    return form.checks.some((check) => check.protocol === protocol);
  }

  /** add stages a new protocol with editable targets; it starts probing only after save. */
  protected add(protocol: Check["protocol"]): void {
    const draft = this.draft();
    if (!draft || this.hasCheck(draft, protocol)) return;
    draft.checks.push({
      protocol,
      targets: "",
      intervalSeconds: 30,
      timeoutSeconds: 3,
      ...(protocol === "UDP" ? { dnsName: "example.com" } : {}),
    });
  }

  /** remove stages removal while retaining the option to cancel the complete edit. */
  protected remove(protocol: Check["protocol"]): void {
    if (!this.draft()) this.edit();
    const draft = this.draft();
    if (draft)
      this.draft.set({
        ...draft,
        checks: draft.checks.filter((check) => check.protocol !== protocol),
      });
  }

  /** save validates the draft and performs exactly one complete update, retaining edits on failure. */
  protected save(): void {
    const draft = this.draft();
    if (!draft || this.saving()) return;
    if (
      !this.original ||
      !sameQualitySettings(this.original, this.settings())
    ) {
      this.notices.show(
        "warn",
        "Настройки на шлюзе изменились. Отмените правки и откройте актуальные настройки.",
      );
      return;
    }
    const settings = {
      windowMinutes: draft.windowMinutes,
      checks: draft.checks.map((check) => ({
        ...check,
        targets: check.targets
          .split(/\r?\n/u)
          .map((target) => target.trim())
          .filter(Boolean),
      })),
    };
    if (!isQualitySettings(settings)) {
      this.notices.show(
        "error",
        "Проверьте цели и интервалы. Для UDP нужны два разных IP на порту 53 и доменное имя. Тайм-аут не должен превышать интервал.",
      );
      return;
    }
    this.saving.set(true);
    this.api
      .updateQualitySettings(settings)
      .pipe(timeout(15000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (body: unknown) => {
          this.saving.set(false);
          if (
            !isQualitySettings(body) ||
            !sameQualitySettings(settings, body)
          ) {
            this.notices.show(
              "error",
              "Шлюз вернул некорректное подтверждение настроек.",
            );
            this.saved.emit();
            return;
          }
          this.draft.set(null);
          this.notices.show("success", "Настройки проверок сохранены.");
          this.saved.emit();
        },
        error: (error: unknown) => {
          this.saving.set(false);
          const body: unknown =
            error instanceof HttpErrorResponse ? error.error : null;
          const detail =
            error instanceof HttpErrorResponse &&
            error.status === 422 &&
            typeof body === "object" &&
            body !== null &&
            "detail" in body &&
            typeof body.detail === "string"
              ? body.detail
              : "";
          this.notices.show(
            "error",
            detail ||
              "Не удалось сохранить настройки проверок. Проверьте доступность шлюза и параметры целей.",
          );
          this.saved.emit();
        },
      });
  }
}
