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
import { ButtonDirective } from "primeng/button";
import { Connections } from "./connections";
import { Groups } from "./groups";
import { type Page } from "./pages";
import { SnapshotState } from "./snapshot-state";

/** SnapshotScreen presents shared loading and retry controls for both read-only routes. */
@Component({
  selector: "hestia-snapshot-screen",
  imports: [ButtonDirective, Groups, Connections, Details, RouterLink],
  templateUrl: "./snapshot-screen.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class SnapshotScreen {
  readonly page = input.required<Page>();
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
    const labels = { group: "Группа", list: "Доменный список", exit: "Выход" };
    return labels[selected.kind] + " " + selected.id;
  });
}
