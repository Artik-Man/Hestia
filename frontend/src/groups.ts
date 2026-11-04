import {
  afterNextRender,
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  Injector,
  input,
} from "@angular/core";
import { CdkDrag, CdkDragHandle, CdkDropList } from "@angular/cdk/drag-drop";
import { RouterLink } from "@angular/router";
import type { Snapshot } from "./api/generated/model/snapshot";
import { GroupsState } from "./groups-state";

/** Groups displays a sortable working order and availability from the latest validated gateway snapshot. */
@Component({
  selector: "hestia-groups",
  imports: [RouterLink, CdkDrag, CdkDropList, CdkDragHandle],
  templateUrl: "./groups.html",
  styleUrl: "./groups.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Groups {
  readonly snapshot = input.required<Snapshot>();
  protected readonly order = inject(GroupsState);
  private readonly injector = inject(Injector);
  protected readonly health = computed(
    () =>
      new Map(
        this.snapshot().groups.flatMap((group) =>
          group.exits.map((exit) => [exit.id, exit.available] as const),
        ),
      ),
  );

  /** keyboardMove moves the focused item with arrow keys and restores focus to its handle after DOM reordering. */
  protected keyboardMove(
    event: KeyboardEvent,
    index: number,
    groupId?: string,
  ): void {
    if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
    event.preventDefault();
    const handle = event.currentTarget;
    this.order.move(index, index + (event.key === "ArrowUp" ? -1 : 1), groupId);
    if (handle instanceof HTMLButtonElement)
      afterNextRender(() => handle.focus(), { injector: this.injector });
  }
}
