import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
} from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { ActivatedRoute, RouterLink } from "@angular/router";
import { Details, readSelection } from "./details";
import { BindingWrite } from "./binding";
import { ButtonDirective } from "primeng/button";
import { Connections } from "./connections";
import { DomainLists } from "./domain-lists";
import { GroupsState } from "./groups-state";
import { Groups } from "./groups";
import { type Page } from "./pages";
import { groupName } from "./snapshot";
import { SnapshotState } from "./snapshot-state";

/** SnapshotScreen presents shared loading and retry controls for routes backed by the shared snapshot. */
@Component({
  selector: "hestia-snapshot-screen",
  imports: [
    ButtonDirective,
    Groups,
    DomainLists,
    Connections,
    Details,
    RouterLink,
  ],
  templateUrl: "./snapshot-screen.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SnapshotScreen {
  readonly page = input.required<Page>();
  protected readonly order = inject(GroupsState);
  protected readonly binding = inject(BindingWrite);
  protected readonly state = inject(SnapshotState);
  private readonly route = inject(ActivatedRoute);
  private readonly params = toSignal(this.route.queryParamMap, {
    initialValue: this.route.snapshot.queryParamMap,
  });
  protected readonly selected = computed(() =>
    readSelection(this.page().path, this.params()),
  );
  protected readonly heading = computed(() => {
    const selected = this.selected();
    if (!selected) return this.page().label;
    if (selected.kind === "invalid") return "Карточка недоступна";
    const labels = { group: "Группа", list: "Доменный список" };
    const view = this.state.view();
    const name =
      selected.kind === "group" && view.kind === "ready"
        ? groupName(view.snapshot.groups, selected.id)
        : selected.kind === "list" && view.kind === "ready"
          ? (view.snapshot.lists.find((list) => list.id === selected.id)
              ?.name ?? selected.id)
          : selected.id;
    return labels[selected.kind] + " " + name;
  });
}
