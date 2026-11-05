import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
} from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { ActivatedRoute, RouterLink } from "@angular/router";
import {
  Details,
  readSelection,
} from "../../core/components/details/details.component";
import { BindingWrite } from "../../core/services/binding-write.service";
import { ButtonDirective } from "primeng/button";
import { Connections } from "../../core/components/connections/connections.component";
import { DomainLists } from "../../core/components/domain-lists/domain-lists.component";
import { GroupsState } from "../../core/services/groups-state.service";
import { Groups } from "../../core/components/groups/groups.component";
import { type Page } from "../pages";
import { groupName } from "../../core/models/snapshot";
import { SnapshotState } from "../../core/services/snapshot-state.service";

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
  templateUrl: "./snapshot-screen.component.html",
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
