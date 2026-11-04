import { ChangeDetectionStrategy, Component, input } from "@angular/core";
import { RouterLink } from "@angular/router";
import type { RuleList } from "./api/generated/model/ruleList";

/** DomainLists shows every saved list, including lists without a group. */
@Component({
  selector: "hestia-domain-lists",
  imports: [RouterLink],
  templateUrl: "./domain-lists.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DomainLists {
  readonly lists = input.required<readonly RuleList[]>();
}
