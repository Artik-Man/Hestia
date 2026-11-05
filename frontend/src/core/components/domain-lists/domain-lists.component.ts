import { Tooltip } from "primeng/tooltip";
import { Notifications } from "../../services/notifications.service";
import { groupName, isRuleList } from "../../models/snapshot";
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  output,
  signal,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { PanelService } from "../../services/api/generated/api/panel.service";
import { SnapshotState } from "../../services/snapshot-state.service";
import { timeout } from "rxjs";
import { FormControl, ReactiveFormsModule } from "@angular/forms";
import type { Group } from "../../services/api/generated/model/group";
import type { RuleList } from "../../services/api/generated/model/ruleList";
import { ButtonDirective } from "primeng/button";
import { Dialog } from "primeng/dialog";
import { InputText } from "primeng/inputtext";
import { Popover } from "primeng/popover";
import { Select } from "primeng/select";
import { Textarea } from "primeng/textarea";

interface EditorValues {
  readonly original: RuleList | null;
  readonly name: string;
  readonly group: string;
  readonly masks: string;
}

/** invalidMasks returns distinct invalid wildcard suffixes while preserving their entered spelling. */
function invalidMasks(masks: readonly string[]): readonly string[] {
  const invalid = masks.filter((mask) => {
    if (!mask.startsWith("*.")) return true;
    const suffix = mask.slice(2).replace(/\.$/u, "");
    return (
      suffix.length === 0 ||
      suffix.length > 253 ||
      !suffix
        .split(".")
        .every((label) =>
          /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(label),
        )
    );
  });
  return [...new Set(invalid)];
}

/** DomainLists edits gateway lists from the overview or a selected list card. */
@Component({
  selector: "hestia-domain-lists",
  imports: [
    Tooltip,
    ButtonDirective,
    Dialog,
    InputText,
    Popover,
    ReactiveFormsModule,
    Select,
    Textarea,
  ],
  templateUrl: "./domain-lists.component.html",
  styleUrl: "./domain-lists.component.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DomainLists {
  private readonly notifications = inject(Notifications);
  protected readonly groupName = groupName;
  readonly lists = input.required<readonly RuleList[]>();
  readonly groups = input.required<readonly Group[]>();
  readonly removed = output<void>();
  readonly selected = input<RuleList>();
  private readonly api = inject(PanelService);
  private readonly snapshot = inject(SnapshotState);
  protected readonly pending = signal(false);
  protected readonly failure = signal("");
  protected readonly needsRefresh = signal(false);
  protected readonly deleting = signal<RuleList | null>(null);
  protected readonly editor = signal<EditorValues | null>(null);
  protected readonly masks = computed(() =>
    (this.editor()?.masks ?? "")
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter(Boolean),
  );
  protected readonly invalid = computed(() => invalidMasks(this.masks()));
  protected readonly nameInvalid = computed(() => {
    const name = this.editor()?.name.trim() ?? "";
    return [...name].length > 80 || /\p{Cc}/u.test(name);
  });
  protected readonly valid = computed(
    () =>
      !!this.editor()?.name.trim() &&
      !this.nameInvalid() &&
      this.masks().length <= 1024 &&
      this.invalid().length === 0,
  );
  protected readonly maskHelpOpen = signal(false);
  protected readonly groupControl = new FormControl("", { nonNullable: true });
  protected editorTrigger?: HTMLButtonElement;
  private maskHelpHideTimer?: ReturnType<typeof setTimeout>;

  /** groupOptions builds the PrimeNG select choices, including an explicit unassigned option. */
  protected groupOptions(): { label: string; value: string }[] {
    return [
      { label: "Группа не назначена", value: "" },
      ...this.groups().map((group) => ({
        label: group.name ?? group.id,
        value: group.id,
      })),
    ];
  }

  /** create opens an empty form for a new gateway list. */
  protected create(trigger: HTMLButtonElement): void {
    this.editorTrigger = trigger;
    this.open({ original: null, name: "", group: "", masks: "" });
  }

  /** edit keeps the exact record observed at open time for the gateway's conflict check. */
  protected edit(list: RuleList, trigger: HTMLButtonElement): void {
    this.editorTrigger = trigger;
    this.open({
      original: list,
      name: list.name ?? list.id,
      group: list.group,
      masks: list.masks.join("\n"),
    });
  }

  /** confirmDeletion retains the selected snapshot for the conditional DELETE after explicit confirmation. */
  protected confirmDeletion(list: RuleList, trigger: HTMLButtonElement): void {
    this.editorTrigger = trigger;
    this.failure.set("");
    this.needsRefresh.set(false);
    this.deleting.set(list);
  }

  /** remove deletes the confirmed list once; uncertain results require reading the gateway before retrying. */
  protected remove(): void {
    const list = this.deleting();
    if (!list || this.pending() || this.needsRefresh()) return;
    this.pending.set(true);
    this.api
      .deleteDomainList(list.id, list, "response")
      .pipe(timeout(310000))
      .subscribe({
        next: (response) => {
          this.pending.set(false);
          if (response.status !== 204) {
            this.reportDeletionFailure(0);
            return;
          }
          this.notifications.show(
            "success",
            `Список «${list.name ?? list.id}» удалён.`,
          );
          this.dismiss(true);
          this.removed.emit();
        },
        error: (error: unknown) => {
          this.pending.set(false);
          this.reportDeletionFailure(
            error instanceof HttpErrorResponse ? error.status : 0,
          );
        },
      });
  }

  /** reportDeletionFailure keeps the confirmation open and prevents retrying with stale list fields. */
  private reportDeletionFailure(status: number): void {
    this.needsRefresh.set(true);
    this.failure.set(
      status === 409
        ? "Список изменился или шлюз занят. Обновите списки перед повторной попыткой."
        : status === 404
          ? "Список больше не существует. Обновите списки."
          : "Шлюз не подтвердил удаление. Обновите списки, чтобы проверить результат.",
    );
  }

  /** open stores form values and resets transient help state before PrimeNG displays the dialog. */
  private open(values: EditorValues): void {
    this.failure.set("");
    this.needsRefresh.set(false);
    this.editor.set(values);
    this.groupControl.setValue(values.group);
    this.maskHelpOpen.set(false);
  }

  /** update changes one field in the current modal model without touching gateway data. */
  protected update(field: "name" | "group" | "masks", value: string): void {
    const current = this.editor();
    if (!current || this.pending()) return;
    this.editor.set({ ...current, [field]: value });
  }

  /** save submits one typed write and accepts only a confirmation matching the complete requested list. */
  protected save(): void {
    const current = this.editor();
    if (!current || this.pending() || this.needsRefresh() || !this.valid())
      return;
    const list = {
      name: current.name.trim(),
      group: current.group,
      masks: this.masks(),
    };
    const expected = current.original;
    const operation = expected
      ? this.api.updateDomainList(expected.id, { expected, list }, "response")
      : this.api.createDomainList(list, "response");
    this.pending.set(true);
    this.failure.set("");
    this.groupControl.disable();
    operation.pipe(timeout(310000)).subscribe({
      next: (response) => {
        this.pending.set(false);
        this.groupControl.enable();
        const body: unknown = response.body;
        if (
          response.status !== (expected ? 200 : 201) ||
          !isRuleList(body) ||
          (expected && body.id !== expected.id) ||
          body.name !== list.name ||
          body.group !== list.group ||
          body.enabled !== Boolean(list.group) ||
          body.masks.length !== list.masks.length ||
          body.masks.some((mask, i) => mask !== list.masks[i])
        ) {
          this.reportFailure(0);
          return;
        }
        this.notifications.show("success", `Список «${list.name}» сохранён.`);
        this.dismiss(true);
      },
      error: (error: unknown) => {
        this.pending.set(false);
        this.groupControl.enable();
        this.reportFailure(
          error instanceof HttpErrorResponse ? error.status : 0,
        );
      },
    });
  }

  /** reportFailure preserves the attempted edit and requires a new snapshot when the write outcome is uncertain. */
  private reportFailure(status: number): void {
    if (status === 422 || status === 413) {
      this.failure.set(
        status === 413
          ? "Список слишком большой для сохранения."
          : "Шлюз отклонил значения. Проверьте название, маски и выбранную группу.",
      );
      return;
    }
    this.needsRefresh.set(true);
    this.failure.set(
      status === 409
        ? "Конфликт сохранения. Название занято, список изменился или шлюз занят. Обновите списки перед повторной попыткой."
        : status === 404
          ? "Список или выбранная группа больше не существует. Обновите списки перед повторной попыткой."
          : "Шлюз не подтвердил сохранение. Обновите списки, чтобы проверить результат.",
    );
  }

  /** dismiss closes the idle dialog and refreshes the snapshot after a confirmed or uncertain write. */
  protected dismiss(reload = this.needsRefresh()): void {
    if (this.pending()) return;
    this.cancelMaskHelpHide();
    this.editor.set(null);
    this.deleting.set(null);
    this.maskHelpOpen.set(false);
    if (reload) this.snapshot.reload(true);
  }

  /** showMaskHelp opens the examples popover at its icon for hover or keyboard focus. */
  protected showMaskHelp(
    event: Event,
    popover: Popover,
    target: HTMLButtonElement,
  ): void {
    this.cancelMaskHelpHide();
    if (!this.maskHelpOpen()) popover.show(event, target);
  }

  /** hideMaskHelp closes the examples popover when its trigger loses hover or focus. */
  protected hideMaskHelp(popover: Popover): void {
    this.cancelMaskHelpHide();
    popover.hide();
  }

  /** scheduleMaskHelpHide waits briefly so pointer travel from the icon to the portaled panel can finish. */
  protected scheduleMaskHelpHide(popover: Popover): void {
    this.cancelMaskHelpHide();
    this.maskHelpHideTimer = setTimeout(() => {
      this.maskHelpHideTimer = undefined;
      popover.hide();
    }, 350);
  }

  /** cancelMaskHelpHide keeps the panel open while the pointer enters its portaled content. */
  protected cancelMaskHelpHide(): void {
    if (this.maskHelpHideTimer !== undefined) {
      clearTimeout(this.maskHelpHideTimer);
      this.maskHelpHideTimer = undefined;
    }
  }

  /** onMaskHelpHidden clears timer and accessible open state after PrimeNG dismisses the panel. */
  protected onMaskHelpHidden(): void {
    this.cancelMaskHelpHide();
    this.maskHelpOpen.set(false);
  }

  /** openMaskHelp supports touch by opening the popover when its icon is tapped. */
  protected openMaskHelp(
    event: MouseEvent,
    popover: Popover,
    target: HTMLButtonElement,
  ): void {
    this.cancelMaskHelpHide();
    if (!this.maskHelpOpen()) popover.show(event, target);
  }
}
