import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  input,
  signal,
  ViewChild,
} from "@angular/core";
import { RouterLink } from "@angular/router";
import type { Group } from "./api/generated/model/group";
import type { RuleList } from "./api/generated/model/ruleList";

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
        .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/iu.test(label))
    );
  });
  return [...new Set(invalid)];
}

/** DomainLists shows gateway lists and explicitly local drafts in one editable list view. */
@Component({
  selector: "hestia-domain-lists",
  imports: [RouterLink],
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
  protected readonly invalid = signal<readonly string[]>([]);
  @ViewChild("editorDialog") private dialog?: ElementRef<HTMLDialogElement>;

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

  /** open stores form values, clears prior validation and shows the native modal dialog. */
  private open(values: EditorValues): void {
    this.editor.set(values);
    this.invalid.set([]);
    this.maskHelpOpen.set(false);
    queueMicrotask(() => this.dialog?.nativeElement.showModal());
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
    this.invalid.set(invalid);
    if (!current.name.trim() || invalid.length > 0) return;
    const sourceId = current.sourceId;
    const key = sourceId ?? `draft-${crypto.randomUUID()}`;
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
    this.dialog?.nativeElement.close();
  }

  /** dismiss closes the dialog and discards unsaved form changes without clearing saved local drafts. */
  protected dismiss(): void {
    this.dialog?.nativeElement.close();
  }

  /** onDialogClose clears transient editor and popover state after close, including Escape. */
  protected onDialogClose(): void {
    this.editor.set(null);
    this.maskHelpOpen.set(false);
    this.invalid.set([]);
  }

  /** draftMasks validates the currently edited text for the live form feedback. */
  protected draftMasks(): readonly string[] {
    return invalidMasks(this.editor()?.masks ?? "");
  }
}
