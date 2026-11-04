import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  Injectable,
  input,
  linkedSignal,
  signal,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { timeout } from "rxjs";
import { PanelService } from "./api/generated/api/panel.service";
import type { BindingChange } from "./api/generated/model/bindingChange";
import type { RuleList } from "./api/generated/model/ruleList";
import type { Group } from "./api/generated/model/group";
import { SnapshotState } from "./snapshot-state";

/** BindingWrite retains the outcome across route changes and re-reads the gateway after every attempt. */
@Injectable({ providedIn: "root" })
export class BindingWrite {
  private readonly api = inject(PanelService);
  private readonly state = inject(SnapshotState);
  readonly pending = signal(false);
  private readonly lastResult = signal<{
    listId: string;
    text: string;
    confirmedGroup?: string;
  } | null>(null);
  readonly result = computed(() => {
    const outcome = this.lastResult();
    const view = this.state.view();
    if (outcome?.confirmedGroup !== undefined && view.kind === "ready") {
      const current = view.snapshot.lists.find(
        (list) => list.id === outcome.listId,
      );
      if (current?.group !== outcome.confirmedGroup) return null;
    }
    return outcome;
  });

  /** apply serializes writes, confirms the complete response and always reconciles the snapshot. */
  apply(change: BindingChange): void {
    if (this.pending() || change.expectedGroup === change.group) return;
    this.pending.set(true);
    this.lastResult.set({
      listId: change.listId,
      text: "Ожидаем подтверждения шлюза…",
    });
    this.api
      .applyListBinding(change, "response")
      .pipe(timeout(310000))
      .subscribe({
        next: (response) => {
          const body: unknown = response.body;
          const confirmed =
            response.status === 200 &&
            typeof body === "object" &&
            body !== null &&
            "group" in body &&
            body.group === change.group &&
            "listId" in body &&
            body.listId === change.listId;
          this.finish(
            change.listId,
            confirmed
              ? "Применено. " +
                  (change.group
                    ? "Группа: " + change.group + "."
                    : "Привязка снята.")
              : "Шлюз не подтвердил запрошенную привязку. Проверьте обновлённый снимок.",
            confirmed ? change.group : undefined,
          );
        },
        error: (error: unknown) => {
          const status = error instanceof HttpErrorResponse ? error.status : 0;
          const text =
            status === 409
              ? "Конфликт изменения. Проверьте текущую привязку в обновлённом снимке."
              : status === 404
                ? "Список или группа отсутствует. Проверьте обновлённый снимок."
                : status === 503
                  ? "Шлюз не подтвердил применение. Запись может быть отключена или служба недоступна."
                  : "Подтверждение не получено. Проверьте текущий снимок перед новой попыткой.";
          this.finish(change.listId, text);
        },
      });
  }
  /** finish publishes feedback separately from snapshot loading and releases the form for the next edit. */
  private finish(listId: string, text: string, confirmedGroup?: string): void {
    this.lastResult.set({
      listId,
      text:
        confirmedGroup === undefined
          ? text
          : text + " Подтверждено " + new Date().toLocaleString("ru-RU") + ".",
      confirmedGroup,
    });
    this.pending.set(false);
    this.state.reload(true);
  }
}

/** BindingEditor submits only changes to an existing list and compares with the displayed group. */
@Component({
  selector: "hestia-binding",
  templateUrl: "./binding.html",
  styleUrl: "./editor.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class BindingEditor {
  readonly list = input.required<RuleList>();
  readonly groups = input.required<readonly Group[]>();
  protected readonly write = inject(BindingWrite);
  protected readonly selected = linkedSignal(() => this.list().group);
  protected readonly unchanged = computed(
    () => this.selected() === this.list().group,
  );
  /** submit sends the chosen replacement together with the group shown when this editor opened. */
  protected submit(): void {
    this.write.apply({
      listId: this.list().id,
      expectedGroup: this.list().group,
      group: this.selected(),
    });
  }
}
