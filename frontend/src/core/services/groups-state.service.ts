import {
  computed,
  inject,
  Injectable,
  linkedSignal,
  signal,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { Notifications } from "./notifications.service";
import { timeout } from "rxjs";
import { PanelService } from "./api/generated/api/panel.service";
import type { OrderedGroup } from "./api/generated/model/orderedGroup";
import {
  type GroupDraft,
  matchesOrder,
  moveTo,
  reconcile,
  sourceOrder,
} from "../models/groups-order";
import { ConnectionCatalog } from "./connection-catalog.service";
import { SnapshotState } from "./snapshot-state.service";

/** GroupsState keeps the working order across reads and sends it only when the operator explicitly saves. */
@Injectable({ providedIn: "root" })
export class GroupsState {
  private readonly catalog = inject(ConnectionCatalog);
  private readonly notifications = inject(Notifications);
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
  readonly newName = signal("");
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
    const id = group
      ? this.catalog.name(group.exits[from])
      : draft.order[from].id;
    this.movement.set(
      id + " — позиция " + (to + 1) + " из " + items.length + ".",
    );
  }

  /** transfer stages the new membership and position; only save sends the complete draft to the gateway. */
  transfer(
    id: string,
    expectedGroup: string,
    group: string,
    priority: number,
  ): void {
    const draft = this.draft();
    const source = draft.order.find((item) => item.id === expectedGroup);
    const target = draft.order.find((item) => item.id === group);
    if (
      this.pending() ||
      draft.changedSource ||
      !source ||
      !target ||
      source === target ||
      !source.exits.includes(id) ||
      priority < 1 ||
      priority > target.exits.length + 1
    )
      return;
    const exits = [...target.exits];
    exits.splice(priority - 1, 0, id);
    const order = draft.order.map((item) =>
      item === source
        ? { ...item, exits: item.exits.filter((exit) => exit !== id) }
        : item === target
          ? { ...item, exits }
          : item,
    );
    this.working.set({ ...draft, order });
    this.movement.set(this.catalog.name(id) + " — позиция " + priority + ".");
  }

  /** reset discards this tab's unsaved proposal and returns to the latest snapshot order. */
  reset(): void {
    if (this.pending()) return;
    const source = this.source();
    if (!source) return;
    this.working.set({ baseline: source, order: source, changedSource: false });
    this.movement.set("Показан порядок шлюза.");
  }

  readonly nameMessage = signal("");

  /** saveName validates the name locally, then preserves the draft on a recoverable gateway rejection. */
  saveName(previous: string | null, onComplete: () => void): void {
    if (this.pending() || this.dirty() || this.draft().changedSource) return;
    const name = this.newName().trim();
    if (!name || [...name].length > 80 || /\p{Cc}/u.test(name)) {
      this.nameMessage.set(
        "Введите от 1 до 80 символов без управляющих знаков.",
      );
      return;
    }
    const view = this.snapshot.view();
    if (view.kind !== "ready") return;
    if (
      view.snapshot.groups.some(
        (group) => group.id !== previous && (group.name ?? group.id) === name,
      )
    ) {
      this.nameMessage.set("Группа с таким названием уже существует.");
      return;
    }
    this.pending.set(true);
    this.nameMessage.set("");
    const operation =
      previous === null
        ? this.api.createGroup({ name }, "response")
        : this.api.renameGroup(previous, { name }, "response");
    operation.pipe(timeout(310000)).subscribe({
      next: (response) => {
        this.pending.set(false);
        const body: unknown = response.body;
        if (
          response.status !== (previous === null ? 201 : 200) ||
          typeof body !== "object" ||
          body === null ||
          !("id" in body) ||
          typeof body.id !== "string" ||
          !body.id ||
          (previous !== null && body.id !== previous) ||
          !("name" in body) ||
          body.name !== name
        ) {
          onComplete();
          this.finish(
            "Шлюз вернул неожиданное подтверждение. Проверьте список групп.",
          );
          return;
        }
        onComplete();
        this.finish(
          previous === null
            ? `Группа «${name}» создана.`
            : `Название группы изменено на «${name}».`,
          "success",
        );
      },
      error: (error: unknown) => {
        this.pending.set(false);
        const status = error instanceof HttpErrorResponse ? error.status : 0;
        if (status === 409 || status === 422) {
          this.notifications.show(
            "error",
            status === 409
              ? "Название уже занято или шлюз выполняет другое изменение."
              : "Шлюз отклонил название группы.",
          );
          return;
        }
        onComplete();
        this.finish(
          status === 404
            ? "Исходная группа больше не существует."
            : "Шлюз не подтвердил сохранение. Проверьте список групп.",
        );
      },
    });
  }

  /** deletionBlock explains which dependency an operator must remove before deleting a group. */
  deletionBlock(id: string): string {
    const view = this.snapshot.view();
    if (view.kind !== "ready") return "Дождитесь загрузки списка групп.";
    const group = view.snapshot.groups.find((item) => item.id === id);
    if (!group) return "Группа больше не существует.";
    if (view.snapshot.groups[0]?.id === id || group.isDefault)
      return "Группу по умолчанию нельзя удалить.";
    if (group.exits.length)
      return "Сначала перенесите подключения этой группы.";
    return "";
  }

  /** deleteGroup sends a confirmed deletion of an unused group, then reloads authoritative state. */
  deleteGroup(id: string, onComplete: () => void): void {
    if (
      this.pending() ||
      this.dirty() ||
      this.draft().changedSource ||
      this.deletionBlock(id)
    )
      return;
    const view = this.snapshot.view();
    if (view.kind !== "ready") return;
    const group = view.snapshot.groups.find((item) => item.id === id);
    if (!group) return;
    this.pending.set(true);
    this.api
      .deleteGroup(id, "response")
      .pipe(timeout(310000))
      .subscribe({
        next: (response) => {
          onComplete();
          if (response.status === 204 && response.body === null)
            this.finish(
              `Группа «${group.name ?? group.id}» удалена.`,
              "success",
            );
          else
            this.finish("Шлюз не подтвердил удаление. Проверьте список групп.");
        },
        error: (error: unknown) => {
          onComplete();
          const status = error instanceof HttpErrorResponse ? error.status : 0;
          this.finish(
            status === 409
              ? "Шлюз занят или группа теперь используется. Проверьте обновлённый список."
              : status === 404
                ? "Группа больше не существует."
                : "Шлюз не подтвердил удаление. Проверьте список групп.",
          );
        },
      });
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
            confirmed ? "success" : "error",
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
  private finish(
    message: string,
    severity: "success" | "error" = "error",
  ): void {
    this.notifications.show(severity, message);
    this.snapshot.reload(true);
    this.pending.set(false);
  }
}
