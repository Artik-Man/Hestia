import {
  ChangeDetectionStrategy,
  Component,
  input,
  output,
  signal,
  OnChanges,
  inject,
  ViewChild,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { FormBuilder, ReactiveFormsModule, Validators } from "@angular/forms";
import { firstValueFrom } from "rxjs";
import type { Group } from "./api/generated/model/group";
import type { AWGConnection } from "./api/generated/model/aWGConnection";
import type { AWGSaveRequest } from "./api/generated/model/aWGSaveRequest";
import type { AWGUpdateRequest } from "./api/generated/model/aWGUpdateRequest";
import { PanelService } from "./api/generated/api/panel.service";
import { ButtonDirective } from "primeng/button";
import { FileUpload, type FileSelectEvent } from "primeng/fileupload";
import { InputNumber } from "primeng/inputnumber";
import { InputText } from "primeng/inputtext";
import { Select } from "primeng/select";

/** ProfileDraft uploads a selected WireGuard or AmneziaWG .conf through the typed API service. */
@Component({
  selector: "hestia-profile-draft",
  imports: [
    ButtonDirective,
    FileUpload,
    InputNumber,
    InputText,
    ReactiveFormsModule,
    Select,
  ],
  templateUrl: "./profile-draft.html",
  styleUrl: "./editor.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProfileDraft implements OnChanges {
  readonly groups = input.required<readonly Group[]>();
  readonly existingIDs = input<readonly string[]>([]);
  readonly connection = input<AWGConnection | null>(null);
  readonly exit = input<string | null>(null);
  readonly closed = output<void>();
  readonly saved = output<AWGConnection>();
  protected readonly selectedConfig = signal<File | null>(null);
  protected readonly selectedCandidate = signal<File | null>(null);
  protected readonly configError = signal("");
  protected readonly report = signal("");
  protected readonly submitting = signal(false);
  protected readonly checked = signal(false);
  @ViewChild("configUpload") private configUpload?: FileUpload;
  private readonly builder = inject(FormBuilder).nonNullable;
  private readonly panel = inject(PanelService);
  protected readonly form = this.builder.group({
    id: ["", Validators.required],
    group: ["", Validators.required],
    priority: [1, [Validators.required, Validators.min(1)]],
  });

  /** groupOptions returns the immutable group snapshot in the mutable array shape expected by PrimeNG Select. */
  protected groupOptions(): Group[] {
    return [...this.groups()];
  }

  /** ngOnChanges clears selected file data and loads identity and order from the displayed snapshot. */
  ngOnChanges(): void {
    const saved = this.connection();
    const id = saved?.id ?? this.exit();
    const group = this.groups().find((item) =>
      item.exits.some((candidate) => candidate.id === id),
    );
    this.configUpload?.clear();
    this.clearSelectedConfig();
    this.form.reset({
      id: id ?? "",
      group: group?.id ?? "",
      priority:
        saved?.priority ??
        (group
          ? group.exits.findIndex((candidate) => candidate.id === id) + 1
          : 1),
    });
  }

  /** priorityLimit returns the largest valid position without counting exits already present in the group snapshot twice. */
  protected priorityLimit(): number {
    const selectedGroup = this.groups().find(
      (group) => group.id === this.form.controls.group.value,
    );
    if (!selectedGroup) return 1;
    return this.priorityCapacity(selectedGroup);
  }

  /** priorityCapacity accounts for an edited exit only when it already belongs to the selected group's exit list. */
  private priorityCapacity(group: Group): number {
    const currentID = this.connection()?.id;
    const includesCurrent =
      currentID !== undefined &&
      group.exits.some((exit) => exit.id === currentID);
    return group.exits.length + (includesCurrent ? 0 : 1);
  }

  /** selectConfig accepts one nonempty .conf file locally and reports unsupported filenames without reading its contents. */
  protected selectConfig(event: FileSelectEvent): void {
    const file = event.files[0];
    if (!file) return;
    this.report.set("");
    this.checked.set(false);
    if (!file.name.toLowerCase().endsWith(".conf")) {
      this.selectedConfig.set(null);
      this.selectedCandidate.set(file);
      this.configError.set("Выберите файл с расширением .conf.");
      return;
    }
    if (file.size === 0) {
      this.selectedConfig.set(null);
      this.selectedCandidate.set(file);
      this.configError.set("Файл конфигурации пуст.");
      return;
    }
    if (file.size > 32 * 1024) {
      this.selectedConfig.set(null);
      this.selectedCandidate.set(file);
      this.configError.set("Размер файла не должен превышать 32 КиБ.");
      return;
    }
    this.selectedConfig.set(file);
    this.selectedCandidate.set(file);
    this.configError.set("");
    this.checked.set(false);
    this.report.set("");
  }

  /** clearSelectedConfig forgets the chosen browser file and its validation message. */
  protected clearSelectedConfig(): void {
    this.selectedConfig.set(null);
    this.selectedCandidate.set(null);
    this.configError.set("");
    this.checked.set(false);
    this.report.set("");
  }

  /** clearConfig clears PrimeNG's queue and the local reference to the selected file. */
  protected clearConfig(upload: FileUpload): void {
    upload.clear();
    this.clearSelectedConfig();
  }

  /** fileSize formats the selected file size for the local form summary. */
  protected fileSize(size: number): string {
    return size < 1024 * 1024
      ? `${Math.max(1, Math.round(size / 1024))} КБ`
      : `${(size / (1024 * 1024)).toFixed(1)} МБ`;
  }

  /** check submits a temporary profile probe and never persists or activates the candidate. */
  protected async check(): Promise<void> {
    const file = this.selectedConfig();
    if (!file) {
      this.report.set("Выберите файл конфигурации .conf.");
      return;
    }
    this.submitting.set(true);
    this.checked.set(false);
    this.report.set("");
    try {
      const result = await firstValueFrom(
        this.panel.checkAWGProfile({ profile: await file.text() }),
      );
      if (this.selectedConfig() !== file) {
        this.report.set(
          "Файл изменился во время проверки. Проверьте его повторно.",
        );
        return;
      }
      this.checked.set(true);
      this.report.set(
        result.routeReady
          ? "Временная проверка и маршрут выхода подтверждены."
          : "Handshake AmneziaWG подтверждён. Профиль можно сохранить; маршрут через него пока не включён.",
      );
    } catch (error: unknown) {
      this.report.set(this.checkError(error));
    } finally {
      this.submitting.set(false);
    }
  }

  /** submit persists only a profile whose temporary runtime check succeeded. */
  protected async submit(): Promise<void> {
    const value = this.form.getRawValue();
    const group = this.groups().find((item) => item.id === value.group);
    const currentID = this.connection()?.id ?? this.exit();
    this.form.markAllAsTouched();
    if (!this.selectedConfig()) {
      this.report.set(
        "Выберите файл конфигурации WireGuard с расширением .conf.",
      );
      return;
    }
    if (!this.checked()) {
      this.report.set("Сначала проверьте профиль AmneziaWG.");
      return;
    }
    if (!group) {
      this.report.set("Выберите существующую группу.");
      return;
    }
    if (
      !/^[a-z][a-z0-9-]{0,62}$/u.test(value.id) ||
      (value.id !== currentID &&
        this.groups().some(
          (item) =>
            item.id === value.id ||
            item.exits.some((candidate) => candidate.id === value.id),
        )) ||
      (currentID === null && this.existingIDs().includes(value.id))
    ) {
      this.report.set(
        "Укажите свободный ID: латинская строчная буква в начале, затем буквы, цифры или дефис (до 63 символов).",
      );
      return;
    }
    const capacity = this.priorityCapacity(group);
    if (
      !Number.isInteger(value.priority) ||
      value.priority < 1 ||
      value.priority > capacity
    ) {
      this.report.set(
        `Приоритет должен быть целым числом от 1 до ${capacity}.`,
      );
      return;
    }
    const file = this.selectedConfig();
    if (!file) {
      this.report.set("Выберите корректный файл .conf.");
      return;
    }
    this.submitting.set(true);
    this.report.set("");
    try {
      const config = await file.text();
      let connection: AWGConnection;
      const saved = this.connection();
      if (saved) {
        const request: AWGUpdateRequest = {
          group: value.group,
          priority: value.priority,
          profile: config,
        };
        connection = await firstValueFrom(
          this.panel.updateAWGConnection(saved.id, request),
        );
      } else {
        const request: AWGSaveRequest = {
          id: value.id,
          group: value.group,
          priority: value.priority,
          profile: config,
        };
        connection = await firstValueFrom(
          this.panel.createAWGConnection(request),
        );
      }
      this.report.set(
        "Профиль сохранён, подключение запущено и добавлено в выбранную группу на указанной позиции.",
      );
      this.saved.emit(connection);
      this.configUpload?.clear();
      this.clearSelectedConfig();
    } catch (error: unknown) {
      this.report.set(this.saveError(error));
    } finally {
      this.submitting.set(false);
    }
  }

  /** checkError maps probe failures to safe messages without exposing config values. */
  private checkError(error: unknown): string {
    if (!(error instanceof HttpErrorResponse)) {
      return "Не удалось проверить профиль. Проверьте соединение и повторите попытку.";
    }
    switch (error.status) {
      case 422:
        return "Шлюз отклонил файл. Проверьте формат профиля AmneziaWG 3.1.";
      case 503:
        return "Проверка userspace-коннектора недоступна или handshake не подтверждён.";
      default:
        return "Не удалось проверить профиль AmneziaWG.";
    }
  }

  /** saveError maps API failures to safe messages without exposing profile data. */
  private saveError(error: unknown): string {
    if (!(error instanceof HttpErrorResponse)) {
      return "Не удалось отправить профиль на шлюз. Проверьте соединение и повторите попытку.";
    }
    switch (error.status) {
      case 409:
        return "Такой ID подключения уже существует.";
      case 422:
        return "Шлюз отклонил файл или параметры подключения. Проверьте формат .conf, ID, группу и приоритет.";
      case 503:
        return "Управление WireGuard/AmneziaWG не включено или шлюз не подтвердил сохранение.";
      default:
        return "Не удалось сохранить профиль на шлюзе. Повторите попытку.";
    }
  }
}
