import {
  ChangeDetectionStrategy,
  Component,
  input,
  linkedSignal,
} from "@angular/core";
import type { Group } from "./api/generated/model/group";
import type { RuleList } from "./api/generated/model/ruleList";

/** GroupsRemoval previews a proposed deletion separately from the gateway's reorder operation. */
@Component({
  selector: "hestia-groups-removal",
  templateUrl: "./groups-removal.html",
  styleUrl: "./editor.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GroupsRemoval {
  readonly group = input.required<Group>();
  readonly lists = input.required<readonly RuleList[]>();
  protected readonly preview = linkedSignal({
    source: () => this.group().id,
    computation: () => false,
  });
}
