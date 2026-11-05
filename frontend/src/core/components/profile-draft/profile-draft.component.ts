import { Tooltip } from "primeng/tooltip";
import { Toast } from "primeng/toast";
import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  computed,
  DestroyRef,
  ElementRef,
  inject,
  input,
  OnChanges,
  output,
  signal,
  ViewChild,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { FormBuilder, ReactiveFormsModule } from "@angular/forms";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { firstValueFrom } from "rxjs";
import type { Group } from "../../services/api/generated/model/group";
import {
  isAWGConnection,
  isConnectionUUID,
  isConnectionName,
  isUnderlayOrder,
} from "../../models/awg-connection";
import type { AWGConnection } from "../../services/api/generated/model/aWGConnection";
import { PanelService } from "../../services/api/generated/api/panel.service";
import { ConnectionCatalog } from "../../services/connection-catalog.service";
import { Notifications } from "../../services/notifications.service";
import { ButtonDirective } from "primeng/button";
import { InputText } from "primeng/inputtext";
import {
  buildWireGuardConfig,
  fieldLabel,
  localFields,
  maxProfileBytes,
  optionalFields,
  parseWireGuardConfig,
  placeholders,
  remoteFields,
  WireGuardFormError,
  type WireGuardField,
  type WireGuardValues,
} from "./wireguard-fields";

/** ProfileDraft edits the fields of a single manually entered, imported or stored WireGuard/AWG profile in a modal dialog. */
@Component({
  selector: "hestia-profile-draft",
  imports: [Tooltip, Toast, ButtonDirective, InputText, ReactiveFormsModule],
  templateUrl: "./profile-draft.component.html",
  styleUrl: "./profile-draft.component.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProfileDraft implements OnChanges, AfterViewInit {
  readonly groups = input.required<readonly Group[]>();
  readonly connection = input<AWGConnection | null>(null);
  readonly closed = output<void>();
  readonly saved = output<AWGConnection>();
  protected readonly target = computed(() => this.connection()?.id ?? null);
  protected readonly fieldLabel = fieldLabel;
  protected readonly placeholders = placeholders;
  protected readonly localFields = localFields;
  protected readonly remoteFields = remoteFields;
  protected readonly optionalFields = optionalFields;
  protected readonly values = signal<WireGuardValues>({});
  protected readonly imported = signal("");
  protected readonly underlays = signal<string[]>([]);
  protected readonly choicesOpen = signal(false);
  protected readonly catalog = inject(ConnectionCatalog);
  protected readonly loadingCandidates = this.catalog.loading;
  protected readonly underlayChoices = computed(() =>
    [
      ...new Set([...this.underlays(), ...this.catalog.entries().keys()]),
    ].filter((id) => id !== this.target()),
  );
  protected readonly underlaySummary = computed(() =>
    this.underlays()
      .map((id) => this.catalog.name(id))
      .join(" → "),
  );

  /** toggleChoices refreshes the available transports whenever the chooser opens. */
  protected toggleChoices(): void {
    this.choicesOpen.update((open) => !open);
    if (this.choicesOpen()) this.catalog.reload();
  }

  private dragging: string | null = null;

  /** toggleUnderlay appends a newly enabled transport or removes it while retaining the other priorities. */
  protected toggleUnderlay(id: string): void {
    if (this.underlays().length >= 64 && !this.underlays().includes(id)) return;
    this.underlays.update((ids) =>
      ids.includes(id) ? ids.filter((item) => item !== id) : [...ids, id],
    );
  }

  /** moveUnderlay moves one enabled transport to its requested rank without changing the selected set. */
  protected moveUnderlay(id: string, to: number): void {
    const ids = [...this.underlays()];
    const from = ids.indexOf(id);
    if (from < 0 || to < 0 || to >= ids.length || from === to) return;
    ids.splice(from, 1);
    ids.splice(to, 0, id);
    this.underlays.set(ids);
  }

  /** startUnderlayDrag identifies a selected transport for a local reorder. */
  protected startUnderlayDrag(event: DragEvent, id: string): void {
    this.dragging = id;
    event.dataTransfer?.setData("text/plain", id);
  }

  /** dropUnderlay applies only an internal drag onto another selected transport. */
  protected dropUnderlay(event: DragEvent, id: string): void {
    event.preventDefault();
    if (this.dragging)
      this.moveUnderlay(this.dragging, this.underlays().indexOf(id));
    this.dragging = null;
  }

  /** endUnderlayDrag clears the drag identity after cancellation or a completed drop. */
  protected endUnderlayDrag(): void {
    this.dragging = null;
  }

  protected readonly reading = signal(false);
  protected readonly unavailable = signal(false);
  protected readonly submitting = signal(false);
  @ViewChild("editor", { static: true })
  private dialog!: ElementRef<HTMLDialogElement>;
  private readonly builder = inject(FormBuilder).nonNullable;
  private readonly panel = inject(PanelService);
  private readonly messages = inject(Notifications);
  private readonly destroy = inject(DestroyRef);
  private initialized: string | null | undefined;
  private revision = 0;
  protected readonly form = this.builder.group({
    name: "",
    group: "",
  });

  /** ngAfterViewInit opens the native modal after its focusable controls are attached. */
  ngAfterViewInit(): void {
    this.dialog.nativeElement.showModal();
    if (!this.catalog.loading()) this.catalog.reload();
  }

  /** ngOnChanges initializes a new target once, preserving the current draft as metadata and availability refresh. */
  ngOnChanges(): void {
    const id = this.target();
    if (this.initialized === id) return;
    this.initialized = id;
    this.revision++;
    this.values.set({});
    this.underlays.set([]);
    this.choicesOpen.set(false);
    this.imported.set("");
    this.unavailable.set(false);
    this.reading.set(false);
    const group = this.groups().find((item) =>
      item.exits.some((candidate) => candidate.id === id),
    );
    const initialGroup =
      group ??
      this.groups().find((item) => item.isDefault) ??
      (this.groups().length === 1 ? this.groups()[0] : undefined);
    this.form.reset({
      name: this.connection()?.name ?? "",
      group: this.connection()?.group ?? initialGroup?.id ?? "",
    });
    if (id) void this.loadProfile(id);
  }

  /** loadProfile validates a selected record and populates the form only while this dialog still edits the same target. */
  protected async loadProfile(id: string): Promise<void> {
    const revision = ++this.revision;
    this.reading.set(true);
    this.unavailable.set(false);
    try {
      const data: unknown = await firstValueFrom(
        this.panel
          .getAWGConnectionProfile(id, "body", false, { transferCache: false })
          .pipe(takeUntilDestroyed(this.destroy)),
      );
      if (this.destroy.destroyed || revision !== this.revision) return;
      if (
        typeof data !== "object" ||
        data === null ||
        !("id" in data) ||
        data.id !== id ||
        !("name" in data) ||
        !isConnectionName(data.name) ||
        !("profile" in data) ||
        typeof data.profile !== "string" ||
        !("group" in data) ||
        typeof data.group !== "string" ||
        !/^[a-z][a-z0-9-]{0,62}$/.test(data.group) ||
        !("priority" in data) ||
        typeof data.priority !== "number" ||
        !Number.isInteger(data.priority) ||
        data.priority < 1
      ) {
        throw new Error("Invalid editor response");
      }
      const underlays = "underlays" in data ? data.underlays : [];
      if (!isUnderlayOrder(underlays, id))
        throw new Error("Invalid underlay priority list");
      this.underlays.set(underlays);
      const fields = parseWireGuardConfig(data.profile);
      this.form.reset({ name: data.name, group: data.group });
      this.values.set(fields);
    } catch (error: unknown) {
      if (this.destroy.destroyed || revision !== this.revision) return;
      this.unavailable.set(true);
      this.messages.show(
        "error",
        error instanceof HttpErrorResponse && error.status === 404
          ? "Профиль WireGuard для этого выхода не найден."
          : "Не удалось загрузить сохранённые параметры подключения.",
      );
    } finally {
      if (!this.destroy.destroyed && revision === this.revision)
        this.reading.set(false);
    }
  }

  /** setField updates only the edited directive and clears the previous submission error. */
  protected setField(field: WireGuardField, value: string): void {
    this.values.update((previous) => ({ ...previous, [field]: value }));
  }

  /** importFile replaces protocol values atomically after a bounded, local .conf read and leaves metadata and invalid imports untouched. */
  protected async importFile(input: HTMLInputElement): Promise<void> {
    const file = input.files?.[0];
    input.value = "";
    if (!file || this.submitting() || this.unavailable()) return;
    const revision = ++this.revision;
    this.reading.set(true);
    try {
      if (!file.name.toLowerCase().endsWith(".conf"))
        throw new WireGuardFormError("Выберите файл с расширением .conf.");
      if (!file.size || file.size > maxProfileBytes)
        throw new WireGuardFormError(
          "Выберите непустой файл размером до 32 КиБ.",
        );
      const fields = parseWireGuardConfig(await file.text());
      if (this.destroy.destroyed || revision !== this.revision) return;
      this.values.set(fields);
      this.imported.set(file.name);
    } catch (error: unknown) {
      if (!this.destroy.destroyed && revision === this.revision)
        this.messages.show(
          "error",
          error instanceof WireGuardFormError
            ? error.message
            : "Не удалось прочитать файл конфигурации.",
        );
    } finally {
      if (!this.destroy.destroyed && revision === this.revision)
        this.reading.set(false);
    }
  }

  /** close discards local secrets and emits cancellation unless a save is still in progress. */
  protected close(event?: Event): void {
    event?.preventDefault();
    if (this.submitting()) return;
    this.revision++;
    this.values.set({});
    this.dialog.nativeElement.close();
    this.closed.emit();
  }

  /** submit creates or updates the edited record once, retaining its draft when validation or gateway activation fails. */
  protected async submit(): Promise<void> {
    if (this.reading() || this.unavailable() || this.submitting()) return;
    const { name: enteredName, group } = this.form.getRawValue();
    const name = enteredName.trim();
    const target = this.target();
    if (!isConnectionName(name)) {
      this.messages.show(
        "error",
        "Введите название подключения длиной от 1 до 80 символов без управляющих знаков.",
      );
      return;
    }
    if (!target && !this.groups().some((item) => item.id === group)) {
      this.messages.show("error", "Выберите существующую группу.");
      return;
    }
    this.submitting.set(true);
    try {
      const profile = buildWireGuardConfig(this.values());
      const request = { name, profile, underlays: this.underlays() };
      const connection: unknown = await firstValueFrom(
        target
          ? this.panel.updateAWGConnection(target, request)
          : this.panel.createAWGConnection({ group, ...request }),
      );
      if (this.destroy.destroyed) return;
      if (
        !isAWGConnection(connection) ||
        (target
          ? connection.id !== target
          : !isConnectionUUID(connection.id)) ||
        connection.name !== name ||
        (!target && connection.group !== group)
      ) {
        this.messages.show(
          "error",
          "Шлюз вернул неожиданные данные. Обновите список подключений.",
        );
        return;
      }
      this.values.set({});
      this.dialog.nativeElement.close();
      this.messages.show(
        "success",
        `Подключение «${connection.name}» сохранено.`,
      );
      this.saved.emit(connection);
    } catch (error: unknown) {
      if (!this.destroy.destroyed)
        this.messages.show("error", this.saveError(error));
    } finally {
      if (!this.destroy.destroyed) this.submitting.set(false);
    }
  }

  /** saveError translates validation and API failures without echoing configuration, keys or server bodies. */
  private saveError(error: unknown): string {
    if (error instanceof WireGuardFormError) return error.message;
    if (error instanceof HttpErrorResponse) {
      switch (error.status) {
        case 409:
          return "Не удалось сохранить изменения. Обновите список и проверьте название и выбранные подключения.";
        case 422:
          return "Шлюз отклонил настройки. Проверьте параметры WireGuard и убедитесь, что выбранные подключения не зависят от этого туннеля.";
        case 503:
          return "Шлюз не подтвердил подключение. Проверьте доступность пира и повторите сохранение.";
      }
    }
    return "Не удалось сохранить подключение. Проверьте соединение со шлюзом.";
  }
}
