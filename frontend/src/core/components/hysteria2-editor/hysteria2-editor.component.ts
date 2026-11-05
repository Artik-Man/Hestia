import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  ViewChild,
  DestroyRef,
  inject,
  input,
  output,
  signal,
  OnInit,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { ButtonDirective } from "primeng/button";
import { InputText } from "primeng/inputtext";
import { firstValueFrom } from "rxjs";
import { PanelService } from "../../services/api/generated/api/panel.service";
import type { Group } from "../../services/api/generated/model/group";
import type { Hysteria2Connection } from "../../services/api/generated/model/hysteria2Connection";
import type { Hysteria2WriteRequest } from "../../services/api/generated/model/hysteria2WriteRequest";
import { UnderlayPicker } from "../underlay-picker/underlay-picker.component";
import { Tooltip } from "primeng/tooltip";
import { isConnectionName } from "../../models/awg-connection";
import { isHysteria2Connection } from "../../models/hysteria2-connection";
import { normalizeHysteriaHost } from "../../models/hysteria2-host";
import {
  isPublicCertificateBundle,
  parseClientProfile,
} from "./client-profile";

/** Hysteria2Editor edits a local draft and only submits it when the operator chooses Save. */
@Component({
  selector: "hestia-hysteria2-editor",
  imports: [UnderlayPicker, Tooltip, FormsModule, InputText, ButtonDirective],
  templateUrl: "./hysteria2-editor.component.html",
  styleUrl: "./hysteria2-editor.component.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Hysteria2Editor implements OnInit, AfterViewInit {
  readonly groups = input.required<readonly Group[]>();
  readonly connection = input<Hysteria2Connection | null>(null);
  readonly saved = output<Hysteria2Connection>();
  readonly closed = output<void>();
  @ViewChild("dialog", { static: true })
  private dialog!: ElementRef<HTMLDialogElement>;
  private readonly api = inject(PanelService);
  private readonly destroy = inject(DestroyRef);
  protected readonly reading = signal(false);
  protected readonly readFailed = signal(false);
  protected readonly error = signal("");
  protected readonly notice = signal("");
  protected readonly busy = signal(false);
  protected name = "";
  protected group = "";
  protected readonly underlays = signal<string[]>([]);
  protected server = "";
  protected port = 443;
  protected password = "";
  protected serverName = "";
  protected certificatePEM = "";
  protected requiredCertificate = "";

  /** ngOnInit selects the default group on creation or loads the private profile for the selected editor only. */
  ngOnInit(): void {
    const target = this.connection();
    this.group = this.groups().find((item) => item.isDefault)?.id ?? "";
    if (target) void this.readProfile(target.id);
  }

  /** readProfile validates the detail response and never displays a partially loaded or mismatched profile. */
  private async readProfile(id: string): Promise<void> {
    this.reading.set(true);
    try {
      const detail: unknown = await firstValueFrom(
        this.api.getHysteria2ConnectionProfile(id, "body", false, {
          transferCache: false,
        }),
      );
      if (this.destroy.destroyed) return;
      if (!detail || typeof detail !== "object" || !("password" in detail))
        throw new Error();
      const { password, ...record } = detail;
      if (
        typeof password !== "string" ||
        !password ||
        !isHysteria2Connection(record) ||
        record.id !== id
      )
        throw new Error();
      this.name = record.name;
      this.group = record.group;
      this.server = record.server;
      this.port = record.port;
      this.underlays.set(
        record.underlays ?? (record.underlay ? [record.underlay] : []),
      );
      this.serverName = record.serverName ?? "";
      this.certificatePEM = record.certificatePEM ?? "";
      this.password = password;
    } catch {
      if (this.destroy.destroyed) return;
      this.readFailed.set(true);
      this.error.set(
        "Не удалось прочитать профиль Hysteria 2. Закройте редактор и попробуйте ещё раз.",
      );
    } finally {
      this.reading.set(false);
    }
  }

  /** ngAfterViewInit brings the new editor into the modal focus scope. */
  ngAfterViewInit(): void {
    this.dialog.nativeElement.showModal();
  }

  /** close dismisses the native modal before its parent restores focus to the opener. */
  protected close(event?: Event): void {
    event?.preventDefault();
    if (this.busy()) return;
    this.dialog.nativeElement.close();
    this.closed.emit();
  }

  /** readFile reads one bounded file into the draft, retaining previous values on validation failure. */
  protected async readFile(
    field: HTMLInputElement,
    kind: "yaml" | "cert",
  ): Promise<void> {
    const file = field.files?.[0];
    field.value = "";
    if (!file || this.busy()) return;
    this.busy.set(true);
    this.error.set("");
    try {
      if (file.size > 65536) throw new Error("Размер файла превышает 64 КиБ.");
      const text = await file.text();
      if (kind === "yaml") {
        const parsed = parseClientProfile(text);
        if (
          !normalizeHysteriaHost(parsed.server) ||
          (parsed.serverName && !normalizeHysteriaHost(parsed.serverName))
        )
          throw new Error("Проверьте адрес server и имя tls.sni.");
        this.server = parsed.server;
        this.port = parsed.port;
        this.password = parsed.password;
        this.serverName = normalizeHysteriaHost(parsed.serverName) ?? "";
        this.requiredCertificate = parsed.ca;
        this.clearCertificate();
        this.notice.set(
          parsed.ignoresSocks
            ? "Профиль загружен. Локальный SOCKS5 из файла пропущен."
            : "Профиль загружен.",
        );
      } else {
        if (!isPublicCertificateBundle(text))
          throw new Error("Выберите публичный сертификат в формате PEM.");
        this.certificatePEM = text;
        this.requiredCertificate = "";
      }
    } catch (error: unknown) {
      this.error.set(
        error instanceof Error ? error.message : "Не удалось прочитать файл.",
      );
    } finally {
      this.busy.set(false);
    }
  }

  /** clearCertificate clears the local trust anchor without discarding any imported CA requirement. */
  protected clearCertificate(): void {
    this.certificatePEM = "";
  }

  /** downloadCertificate exports the current draft's public PEM without the client password. */
  protected downloadCertificate(): void {
    if (!this.certificatePEM) return;
    const url = URL.createObjectURL(
      new Blob([this.certificatePEM], { type: "application/x-pem-file" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "hysteria2-ca.pem";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  /** save validates the draft and emits the confirmed public profile after gateway application. */
  protected async save(): Promise<void> {
    if (this.busy() || this.reading() || this.readFailed()) return;
    this.error.set("");
    const server = normalizeHysteriaHost(this.server);
    const serverName = normalizeHysteriaHost(this.serverName);
    if (
      !isConnectionName(this.name.trim()) ||
      !server ||
      (this.serverName && !serverName) ||
      !Number.isInteger(this.port) ||
      this.port < 1 ||
      this.port > 65535 ||
      !this.password ||
      (!this.connection() && !this.group)
    ) {
      this.error.set("Проверьте название, группу, адрес, порт и пароль.");
      return;
    }
    if (this.requiredCertificate && !this.certificatePEM) {
      this.error.set("Выберите сертификат, указанный в tls.ca.");
      return;
    }
    this.busy.set(true);
    const target = this.connection();
    const body: Hysteria2WriteRequest = {
      name: this.name.trim(),
      server,
      port: this.port,
      underlays: this.underlays(),
      serverName: serverName ?? "",
      certificatePEM: this.certificatePEM,
      ...(target ? {} : { group: this.group }),
      password: this.password,
    };
    try {
      const result: unknown = await firstValueFrom(
        target
          ? this.api.updateHysteria2Connection(target.id, body)
          : this.api.createHysteria2Connection(body),
      );
      if (!isHysteria2Connection(result) || (target && result.id !== target.id))
        throw new Error();
      this.dialog.nativeElement.close();
      this.saved.emit(result);
    } catch {
      this.error.set(
        "Не удалось применить подключение. Проверьте параметры и доступность шлюза.",
      );
    } finally {
      this.busy.set(false);
    }
  }
}
