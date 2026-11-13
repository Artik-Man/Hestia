import { Tooltip } from "primeng/tooltip";
import {
  afterNextRender,
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  Injector,
  inject,
  input,
  model,
  output,
  signal,
  viewChild,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { HttpErrorResponse } from "@angular/common/http";
import { FormsModule } from "@angular/forms";
import { Toast } from "primeng/toast";
import { ButtonDirective } from "primeng/button";
import { Dialog } from "primeng/dialog";
import { InputText } from "primeng/inputtext";
import { Textarea } from "primeng/textarea";
import { finalize, Observable, timeout } from "rxjs";
import { PanelService } from "../../services/api/generated/api/panel.service";
import type { QualityCheck } from "../../services/api/generated/model/qualityCheck";
import type { GroupSettings } from "../../services/api/generated/model/groupSettings";
import { Notifications } from "../../services/notifications.service";
import {
  isQualitySettings,
  validCheck,
  qualityProtocols,
  qualityLabel,
  sameQualityCheck,
} from "../../../routes/quality/quality-observations";

type Protocol = QualityCheck["protocol"];

const descriptions: Record<Protocol, string> = {
  UDP: "Доставка DNS-запроса по UDP",
  TCP: "Установка TCP-соединения",
  ICMP: "Ответ на echo-запрос (ping)",
  DNS: "Разрешение доменного имени",
  HTTPS: "HTTPS-запрос с проверкой сертификата",
  HTTP3: "HTTP/3-запрос через QUIC",
};

const suggestedTargets: Record<Protocol, string> = {
  UDP: "1.1.1.1:53\n8.8.8.8:53",
  TCP: "1.1.1.1:443\n8.8.8.8:443",
  ICMP: "1.1.1.1\n8.8.8.8",
  DNS: "1.1.1.1:53\n8.8.8.8:53",
  HTTPS: "",
  HTTP3: "",
};

/** CheckDraft holds the values of just one check; its original settings detect concurrent edits. */
interface CheckDraft {
  protocol: Protocol;
  original?: QualityCheck;
  targets: string;
  intervalSeconds: number | null;
  timeoutSeconds: number | null;
  dnsName: string;
  serverName: string;
  requestPath: string;
}

/** QualityEditor owns independent dialogs for the individual checks and their group scoring window. */
@Component({
  selector: "hestia-quality-settings",
  imports: [
    Toast,
    Tooltip,
    FormsModule,
    ButtonDirective,
    Dialog,
    InputText,
    Textarea,
  ],
  templateUrl: "./quality-report.component.html",
  styleUrl: "../../../styles/quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class QualityEditor {
  readonly settings = model.required<GroupSettings>();
  readonly groupID = input.required<string>();
  readonly groupName = input.required<string>();
  readonly closed = output<void>();
  readonly saved = output<void>();
  protected readonly draft = signal<CheckDraft | null>(null);
  protected readonly windowDraft = signal<{
    original: number;
    minutes: number | null;
  } | null>(null);
  protected readonly deleting = signal<QualityCheck | null>(null);
  protected readonly saving = signal(false);
  protected readonly protocols = qualityProtocols;
  protected readonly descriptions = descriptions;
  protected readonly label = qualityLabel;
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly injector = inject(Injector);
  private readonly targetsField =
    viewChild<ElementRef<HTMLTextAreaElement>>("targetsField");
  private readonly api = inject(PanelService);
  private readonly notices = inject(Notifications);
  private readonly destroyRef = inject(DestroyRef);

  /** check returns the configured check of this type or undefined when it can be added. */
  protected check(protocol: Protocol): QualityCheck | undefined {
    return this.settings().checks.find((c) => c.protocol === protocol);
  }

  /** edit snapshots only the selected check and opens its protocol-specific form. */
  protected edit(protocol: Protocol): void {
    const original = this.check(protocol);
    this.draft.set({
      protocol,
      original,
      targets: original?.targets.join("\n") ?? suggestedTargets[protocol],
      intervalSeconds: original?.intervalSeconds ?? 30,
      timeoutSeconds: original?.timeoutSeconds ?? 3,
      dnsName: original?.dnsName ?? "example.com",
      serverName: original?.serverName ?? "",
      requestPath: original?.requestPath ?? "/",
    });
  }

  /** editWindow initializes the separate editor for the group assessment period. */
  protected editWindow(): void {
    const original = this.settings().windowMinutes;
    this.windowDraft.set({ original, minutes: original });
  }

  /** dismiss closes an idle dialog without writing to the gateway. */
  protected dismiss(): void {
    if (this.saving()) return;
    this.draft.set(null);
    this.windowDraft.set(null);
    this.deleting.set(null);
  }

  /** focusCheck returns keyboard focus to the edit or add button for a closed check dialog. */
  protected focusCheck(protocol: Protocol): void {
    if (!this.draft())
      this.host.nativeElement
        .querySelector<HTMLButtonElement>(
          '[data-quality-editor="' + protocol + '"]',
        )
        ?.focus();
  }

  /** saveCheck writes only the check shown in the current dialog and verifies its confirmation. */
  protected saveCheck(form: HTMLFormElement): void {
    const draft = this.draft();
    if (!draft || this.saving()) return;
    if (!this.current(draft.protocol, draft.original)) return;
    const { protocol, intervalSeconds, timeoutSeconds } = draft;
    const item = {
      protocol,
      intervalSeconds,
      timeoutSeconds,
      targets: draft.targets
        .split(/\r?\n/u)
        .map((t) => t.trim())
        .filter(Boolean),
      ...(protocol === "DNS" || protocol === "UDP"
        ? { dnsName: draft.dnsName.trim() }
        : {}),
      ...(protocol === "HTTPS" || protocol === "HTTP3"
        ? {
            serverName: draft.serverName.trim(),
            requestPath: draft.requestPath.trim(),
          }
        : {}),
    };
    if (!validCheck(item, true)) {
      this.notices.show(
        "error",
        "Проверьте цели, параметры запроса, интервал и тайм-аут.",
        "quality-settings",
      );
      return;
    }
    if (protocol === "TCP") form.focus();
    this.persist(
      this.api.putGroupQualityCheck(this.groupID(), protocol, item),
      (settings) => {
        const check = settings.checks.find(
          (check) => check.protocol === protocol,
        );
        if (!check) return false;
        if (protocol !== "TCP") return sameQualityCheck(check, item);
        return (
          check.targets.length === item.targets.length &&
          check.intervalSeconds === item.intervalSeconds &&
          check.timeoutSeconds === item.timeoutSeconds
        );
      },
      protocol === "TCP" ? draft : undefined,
    );
  }

  /** saveWindow updates the assessment window while retaining every current check. */
  protected saveWindow(): void {
    const draft = this.windowDraft();
    if (!draft || this.saving()) return;
    const current = this.settings();
    if (draft.original !== current.windowMinutes) {
      this.conflict();
      return;
    }
    const minutes = draft.minutes;
    if (
      minutes === null ||
      !Number.isSafeInteger(minutes) ||
      minutes < 1 ||
      minutes > 1440
    )
      return;
    this.persist(
      this.api.putGroupQualityWindow(this.groupID(), {
        windowMinutes: minutes,
      }),
      (settings) => settings.windowMinutes === minutes,
    );
  }

  /** remove deletes exactly the confirmed check and preserves the current window and other checks. */
  protected remove(): void {
    const item = this.deleting();
    if (!item || !this.current(item.protocol, item) || this.saving()) return;
    this.persist(
      this.api.deleteGroupQualityCheck(this.groupID(), item.protocol),
      (settings) =>
        !settings.checks.some((check) => check.protocol === item.protocol),
    );
  }

  /** current detects a gateway change to the specific check affected by the dialog. */
  private current(
    protocol: Protocol,
    original: QualityCheck | undefined,
  ): boolean {
    const now = this.check(protocol);
    if (
      now === original ||
      (now && original && sameQualityCheck(now, original))
    )
      return true;
    this.conflict();
    return false;
  }

  /** conflict tells the operator to reopen a draft after a concurrent change. */
  private conflict(): void {
    this.notices.show(
      "warn",
      "Настройка на шлюзе изменилась. Закройте окно и откройте её снова.",
      "quality-settings",
    );
  }

  /** persist verifies a scoped write and refreshes the TCP editor with saved endpoints or closes the completed dialog. */
  private persist(
    request: Observable<GroupSettings>,
    confirmed: (settings: GroupSettings) => boolean,
    tcpDraft?: CheckDraft,
  ): void {
    this.saving.set(true);
    request
      .pipe(
        timeout(tcpDraft ? 30000 : 15000),
        finalize(() => {
          if (tcpDraft && !this.destroyRef.destroyed)
            afterNextRender(() => this.targetsField()?.nativeElement.focus(), {
              injector: this.injector,
            });
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (body: unknown) => {
          this.saving.set(false);
          if (!isQualitySettings(body) || !confirmed(body)) {
            this.notices.show(
              "error",
              "Шлюз вернул некорректное подтверждение настроек.",
              "quality-settings",
            );
            this.saved.emit();
            return;
          }
          this.settings.set(body);
          if (tcpDraft) {
            const original = this.check(tcpDraft.protocol)!;
            this.draft.set({
              ...tcpDraft,
              original,
              targets: original.targets.join("\n"),
            });
          } else this.dismiss();
          this.notices.show(
            "success",
            "Настройки проверок сохранены.",
            tcpDraft ? "quality-settings" : undefined,
          );
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
            detail || "Не удалось сохранить настройки проверок.",
            "quality-settings",
          );
          this.saved.emit();
        },
      });
  }
}
