import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
} from "@angular/core";
import { RouterLink } from "@angular/router";
import type { Group } from "./api/generated/model/group";

/** Connections lists configured exits in backend order with their priority within each group. */
@Component({
  selector: "hestia-connections",
  imports: [RouterLink],
  templateUrl: "./connections.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Connections {
  readonly groups = input.required<readonly Group[]>();
  protected readonly rows = computed(() =>
    this.groups().flatMap((group) =>
      group.exits.map((exit, index) => ({
        exit,
        group: group.id,
        priority: index + 1,
      })),
    ),
  );
}
