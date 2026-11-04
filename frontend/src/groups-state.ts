import {
  computed,
  inject,
  Injectable,
  linkedSignal,
  signal,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { timeout } from "rxjs";
import { PanelService } from "./api/generated/api/panel.service";
import type { OrderedGroup } from "./api/generated/model/orderedGroup";
import {
  type GroupDraft,
  matchesOrder,
  moveTo,
  reconcile,
  sourceOrder,
} from "./groups-order";
import { SnapshotState } from "./snapshot-state";

/** GroupsState keeps the working order across reads and sends it only when the operator explicitly saves. */
@Injectable({ providedIn: "root" })
export class GroupsState {
  private readonly api = inject(PanelService);
  private readonly snapshot = inject(SnapshotState);
  private readonly source = computed(() => {
    const view = this.snapshot.view();
    return view.kind === "ready" ? sourceOrder(view.snapshot.groups) : null;
  });
  private readonly working = linkedSignal<OrderedGroup[] | null, GroupDraft>({
    source: this.source,
    computation: (actual, previous) => reconcile(actual, previous?.value),
  });
  readonly draft = this.working.asReadonly();
  readonly dirty = computed(
    () => !matchesOrder(this.draft().order, this.draft().baseline),
  );
  readonly pending = signal(false);
  private readonly feedback = signal<{
    message: string;
    confirmed?: OrderedGroup[];
  }>({ message: "" });
  readonly notice = computed(() => {
    const { message, confirmed } = this.feedback();
    const current = this.source();
    return confirmed && current && !matchesOrder(current, confirmed)
      ? ""
      : message;
  });
  readonly movement = signal("");

  /** move changes exactly one ordered array, keeping every group and exit in its original membership. */
  move(from: number, to: number, groupId?: string): void {
    if (this.pending() || this.draft().changedSource) return;
    const draft = this.draft();
    const group = draft.order.find((group) => group.id === groupId);
    if (groupId !== undefined && !group) return;
    const items = group?.exits ?? draft.order;
    if (
      from === to ||
      from < 0 ||
      from >= items.length ||
      to < 0 ||
      to >= items.length
    )
      return;
    const order = group
      ? draft.order.map((item) =>
          item.id === group.id
            ? { ...item, exits: moveTo(item.exits, from, to) }
            : item,
        )
      : moveTo(draft.order, from, to);
    this.working.set({ ...draft, order, changedSource: false });
    const id = group ? group.exits[from] : draft.order[from].id;
    this.movement.set(
      id + " — позиция " + (to + 1) + " из " + items.length + ".",
    );
    this.feedback.set({ message: "" });
  }

  /** reset discards this tab's unsaved proposal and returns to the latest snapshot order. */
  reset(): void {
    if (this.pending()) return;
    const source = this.source();
    if (!source) return;
    this.working.set({ baseline: source, order: source, changedSource: false });
    this.feedback.set({ message: "" });
    this.movement.set("Показан порядок шлюза.");
  }

  /** save compares with the observed gateway topology, confirms the complete result, then refreshes from the gateway. */
  save(): void {
    const draft = this.draft();
    if (
      this.pending() ||
      draft.changedSource ||
      !this.dirty() ||
      !matchesOrder(this.source(), draft.baseline)
    )
      return;
    this.pending.set(true);
    this.feedback.set({ message: "Шлюз применяет порядок…" });
    this.api
      .applyGroupOrder(
        { expected: draft.baseline, groups: draft.order },
        "response",
      )
      .pipe(timeout(310000))
      .subscribe({
        next: (response) => {
          const body: unknown = response.body;
          const confirmed =
            response.status === 200 &&
            typeof body === "object" &&
            body !== null &&
            "groups" in body &&
            matchesOrder(body.groups, draft.order);
          if (confirmed)
            this.working.set({
              baseline: draft.order,
              order: draft.order,
              changedSource: false,
            });
          this.finish(
            confirmed
              ? "Порядок применён шлюзом."
              : "Подтверждение не совпало с отправленным порядком. Проверьте актуальный снимок.",
            confirmed ? draft.order : undefined,
          );
        },
        error: (error: unknown) => {
          const status = error instanceof HttpErrorResponse ? error.status : 0;
          this.finish(
            status === 409
              ? "Конфликт: исходный порядок изменился или шлюз занят. Проверьте обновлённый снимок перед повторной попыткой."
              : status === 503
                ? "Шлюз не подтвердил применение порядка. Проверьте обновлённый снимок."
                : "Подтверждение не получено. Проверьте текущий снимок перед новой попыткой.",
          );
        },
      });
  }

  /** finish publishes the write outcome even if the authoritative snapshot read subsequently fails. */
  private finish(message: string, confirmed?: OrderedGroup[]): void {
    this.feedback.set({ message, confirmed });
    this.snapshot.reload(true);
    this.pending.set(false);
  }
}
