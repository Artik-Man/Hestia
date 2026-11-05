import { Tooltip } from "primeng/tooltip";
import { ConnectionCatalog } from "../../services/connection-catalog.service";
import {
  afterNextRender,
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  OnInit,
  computed,
  inject,
  Injector,
  ElementRef,
  input,
} from "@angular/core";
import {
  CdkDrag,
  CdkDragHandle,
  CdkDropList,
  type CdkDragDrop,
} from "@angular/cdk/drag-drop";
import { FormsModule } from "@angular/forms";
import { Toast } from "primeng/toast";
import { InputText } from "primeng/inputtext";
import { ButtonDirective } from "primeng/button";
import { RouterLink } from "@angular/router";
import type { Snapshot } from "../../services/api/generated/model/snapshot";
import { groupName } from "../../models/snapshot";
import { GroupsState } from "../../services/groups-state.service";

/** Groups displays a sortable working order and availability from the latest validated gateway snapshot. */
@Component({
  selector: "hestia-groups",
  imports: [
    Tooltip,
    FormsModule,
    Toast,
    InputText,
    ButtonDirective,
    RouterLink,
    CdkDrag,
    CdkDropList,
    CdkDragHandle,
  ],
  templateUrl: "./groups.component.html",
  styleUrl: "./groups.component.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Groups implements OnInit {
  protected readonly catalog = inject(ConnectionCatalog);

  /** ngOnInit refreshes gateway names when this view opens. */
  ngOnInit(): void {
    this.catalog.reload();
  }

  readonly snapshot = input.required<Snapshot>();
  protected readonly order = inject(GroupsState);
  private readonly changeDetector = inject(ChangeDetectorRef);
  private readonly injector = inject(Injector);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  protected readonly health = computed(
    () =>
      new Map(
        this.snapshot().groups.flatMap((group) =>
          group.exits.map((exit) => [exit.id, exit.available] as const),
        ),
      ),
  );

  protected deleting: string | null = null;
  protected editing: string | null = null;

  /** groupName displays the stored name or the identifier for groups created before naming support. */
  protected groupName(id: string): string {
    return groupName(this.snapshot().groups, id);
  }

  /** openEditor initializes the name on every open and lets the browser manage modal focus and Escape. */
  protected openEditor(dialog: HTMLDialogElement, group: string | null): void {
    this.editing = group;
    this.order.newName.set(group === null ? "" : this.groupName(group));
    this.order.nameMessage.set("");
    this.changeDetector.detectChanges();
    dialog.showModal();
    dialog.querySelector("input")?.select();
  }

  /** cancelEditor preserves an in-flight write when the user presses Escape. */
  protected cancelEditor(event: Event): void {
    if (this.order.pending()) event.preventDefault();
  }

  /** submitName closes the active dialog when the gateway request completes. */
  protected submitName(dialog: HTMLDialogElement): void {
    this.order.saveName(this.editing, () => dialog.close());
  }

  /** openDeletion shows the selected group and dependencies before asking for confirmation. */
  protected openDeletion(dialog: HTMLDialogElement, id: string): void {
    this.deleting = id;
    this.changeDetector.detectChanges();
    dialog.showModal();
  }

  /** boundLists names the domain lists that will survive deletion without a group binding. */
  protected boundLists(id: string): string[] {
    return this.snapshot()
      .lists.filter((list) => list.group === id)
      .map((list) => list.name ?? list.id);
  }

  /** submitDeletion closes the confirmation once the gateway reports the outcome. */
  protected submitDeletion(dialog: HTMLDialogElement): void {
    if (this.deleting !== null)
      this.order.deleteGroup(this.deleting, () => dialog.close());
  }

  protected readonly exitListIds = computed(() =>
    this.order.draft().order.map((group) => "exits-" + group.id),
  );

  /** dropExit stages the dragged exit at its new position in either list. */
  protected dropExit(event: CdkDragDrop<string, string, string>): void {
    if (!event.isPointerOverContainer) return;
    if (event.previousContainer === event.container) {
      this.order.move(
        event.previousIndex,
        event.currentIndex,
        event.container.data,
      );
    } else {
      this.order.transfer(
        event.item.data,
        event.previousContainer.data,
        event.container.data,
        event.currentIndex + 1,
      );
    }
  }

  /** keyboardMove moves the focused item with arrow keys and restores focus to its handle after DOM reordering. */
  protected keyboardMove(
    event: KeyboardEvent,
    index: number,
    groupId?: string,
  ): void {
    if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
    event.preventDefault();
    const direction = event.key === "ArrowUp" ? -1 : 1;
    if (event.altKey && groupId !== undefined) {
      const groups = this.order.draft().order;
      const from = groups.findIndex((group) => group.id === groupId);
      const to = groups[from + direction];
      const exit = groups[from]?.exits[index];
      if (exit && to) {
        this.order.transfer(exit, groupId, to.id, to.exits.length + 1);
        afterNextRender(
          () =>
            this.host.nativeElement
              .querySelector<HTMLButtonElement>(
                '[data-exit-handle="' + CSS.escape(exit) + '"]',
              )
              ?.focus(),
          { injector: this.injector },
        );
      }
      return;
    }
    const handle = event.currentTarget;
    this.order.move(index, index + direction, groupId);
    if (handle instanceof HTMLButtonElement)
      afterNextRender(() => handle.focus(), { injector: this.injector });
  }
}
