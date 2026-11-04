import { ChangeDetectionStrategy, Component, input } from "@angular/core";
import { RouterLink } from "@angular/router";
import type { Snapshot } from "./api/generated/model/snapshot";

/** Groups presents configured exit order and domain list bindings from the same snapshot. */
@Component({
  selector: "hestia-groups",
  imports: [RouterLink],
  templateUrl: "./groups.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Groups {
  readonly snapshot = input.required<Snapshot>();
}
