import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  linkedSignal,
} from "@angular/core";
import { BindingWrite } from "../../services/binding-write.service";
import type { RuleList } from "../../services/api/generated/model/ruleList";
import type { Group } from "../../services/api/generated/model/group";

/** BindingEditor submits only changes to an existing list and compares with the displayed group. */
@Component({
  selector: "hestia-binding",
  templateUrl: "./binding.component.html",
  styleUrl: "./binding.component.css",
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
