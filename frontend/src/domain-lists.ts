import {
  ChangeDetectionStrategy,
  Component,
  input,
  signal,
} from "@angular/core";
import { FormControl, ReactiveFormsModule } from "@angular/forms";
import { RouterLink } from "@angular/router";
import type { Group } from "./api/generated/model/group";
import type { RuleList } from "./api/generated/model/ruleList";
import { ButtonDirective } from "primeng/button";
import { Dialog } from "primeng/dialog";
import { InputText } from "primeng/inputtext";
import { Popover } from "primeng/popover";
import { Select } from "primeng/select";
import { Textarea } from "primeng/textarea";

interface ListDraft {
  readonly key: string;
  readonly sourceId: string | null;
  readonly name: string;
  readonly group: string;
  readonly masks: readonly string[];
  readonly enabled: boolean;
}

interface EditorValues {
  readonly sourceId: string | null;
  readonly name: string;
  readonly group: string;
  readonly masks: string;
  readonly enabled: boolean;
}

/** invalidMasks checks draft lines against the wildcard DNS suffix form accepted by the routing model. */
function invalidMasks(value: string): readonly string[] {
  const masks = value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  const invalid = masks.filter((mask) => {
    if (!mask.startsWith("*.")) return true;
    const suffix = mask.slice(2).replace(/\.$/u, "");
    return (
      suffix.length === 0 ||
      suffix.length > 253 ||
      !suffix
        .split(".")
        .every((label) =>
          /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(label),
        )
    );
  });
  return [...new Set(invalid)];
}

/** DomainLists shows gateway lists and explicitly local drafts in one editable list view. */
@Component({
  selector: "hestia-domain-lists",
  imports: [
    ButtonDirective,
    Dialog,
    InputText,
    Popover,
    ReactiveFormsModule,
    RouterLink,
    Select,
    Textarea,
  ],
  templateUrl: "./domain-lists.html",
  styleUrl: "./domain-lists.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DomainLists {
  readonly lists = input.required<readonly RuleList[]>();
  readonly groups = input.required<readonly Group[]>();
  protected readonly drafts = signal<readonly ListDraft[]>([]);
  protected readonly editor = signal<EditorValues | null>(null);
  protected readonly maskHelpOpen = signal(false);
  protected readonly groupControl = new FormControl("", { nonNullable: true });
  private draftSequence = 0;
  private maskHelpHideTimer?: ReturnType<typeof setTimeout>;

  /** visibleLists overlays local edits on the gateway snapshot and appends new local-only drafts. */
  protected visibleLists(): readonly ListDraft[] {
    const draftBySource = new Map(
      this.drafts()
        .filter((draft) => draft.sourceId !== null)
        .map((draft) => [draft.sourceId, draft]),
    );
    const gatewayLists = this.lists().map((list) =>
      this.fromGateway(list, draftBySource.get(list.id)),
    );
    return [
      ...gatewayLists,
      ...this.drafts().filter((draft) => draft.sourceId === null),
    ];
  }

  /** groupOptions builds the PrimeNG select choices, including an explicit unassigned option. */
  protected groupOptions(): { label: string; value: string }[] {
    return [
      { label: "Группа не назначена", value: "" },
      ...this.groups().map((group) => ({ label: group.id, value: group.id })),
    ];
  }

  /** hasDraft reports whether a gateway list has a local replacement draft. */
  protected hasDraft(sourceId: string | null): boolean {
    return (
      sourceId !== null &&
      this.drafts().some((draft) => draft.sourceId === sourceId)
    );
  }

  /** fromGateway combines one gateway record with its current local draft, if it has one. */
  private fromGateway(list: RuleList, draft?: ListDraft): ListDraft {
    return (
      draft ?? {
        key: list.id,
        sourceId: list.id,
        name: list.id,
        group: list.group,
        masks: list.masks,
        enabled: list.enabled,
      }
    );
  }

  /** create opens an empty modal and uses a generated temporary key for the local draft. */
  protected create(): void {
    this.open({
      sourceId: null,
      name: "",
      group: "",
      masks: "",
      enabled: true,
    });
  }

  /** edit opens the modal with the latest local draft or gateway values for the selected list. */
  protected edit(list: ListDraft): void {
    this.open({
      sourceId: list.sourceId,
      name: list.name,
      group: list.group,
      masks: list.masks.join("\n"),
      enabled: list.enabled,
    });
  }

  /** open stores form values and resets transient help state before PrimeNG displays the dialog. */
  private open(values: EditorValues): void {
    this.editor.set(values);
    this.groupControl.setValue(values.group);
    this.maskHelpOpen.set(false);
  }

  /** update changes one field in the current modal model without touching gateway data. */
  protected update(field: keyof EditorValues, value: string): void {
    const current = this.editor();
    if (!current || field === "sourceId" || field === "enabled") return;
    this.editor.set({ ...current, [field]: value });
  }

  /** save validates the form and stores a named draft without issuing a request to the gateway. */
  protected save(): void {
    const current = this.editor();
    if (!current) return;
    const invalid = invalidMasks(current.masks);
    if (!current.name.trim() || invalid.length > 0) return;
    const sourceId = current.sourceId;
    const key = sourceId ?? `draft-${Date.now()}-${this.draftSequence++}`;
    const draft: ListDraft = {
      key,
      sourceId,
      name: current.name.trim(),
      group: current.group,
      masks: current.masks
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter(Boolean),
      enabled: current.enabled,
    };
    this.drafts.update((drafts) => [
      ...drafts.filter((existing) => existing.key !== key),
      draft,
    ]);
    this.dismiss();
  }

  /** dismiss hides the PrimeNG dialog and discards unsaved edits without clearing saved local drafts. */
  protected dismiss(): void {
    this.editor.set(null);
    this.onDialogClose();
  }

  /** onDialogVisibilityChange clears the editor state when PrimeNG hides the dialog, including Escape. */
  protected onDialogVisibilityChange(visible: boolean): void {
    if (!visible) this.onDialogClose();
  }

  /** onDialogClose clears transient editor and popover state after closing the dialog. */
  protected onDialogClose(): void {
    this.cancelMaskHelpHide();
    this.editor.set(null);
    this.maskHelpOpen.set(false);
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

  /** maskCount returns the nonempty lines currently entered in the modal. */
  protected maskCount(): number {
    return (this.editor()?.masks ?? "")
      .split(/\r?\n/u)
      .filter((line) => line.trim().length > 0).length;
  }

  /** draftMasks validates the currently edited text for the live form feedback. */
  protected draftMasks(): readonly string[] {
    return invalidMasks(this.editor()?.masks ?? "");
  }
}
