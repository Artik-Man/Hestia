import { groupName } from "../../models/snapshot";
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
} from "@angular/core";
import { BindingEditor } from "../binding/binding.component";
import { DomainLists } from "../domain-lists/domain-lists.component";
import type { ParamMap } from "@angular/router";
import type { RuleList } from "../../services/api/generated/model/ruleList";
import type { Snapshot } from "../../services/api/generated/model/snapshot";
import type { Page } from "../../../routes/pages";

/** A selection identifies exactly one supported object on its parent page. */
export type Selection = { kind: "list"; id: string } | { kind: "invalid" };

/** readSelection returns null for the overview and rejects duplicate or misplaced detail selectors. */
export function readSelection(
  path: Page["path"],
  params: ParamMap,
): Selection | null {
  const values = params.getAll("list");
  if (!values.length) return null;
  if (
    path !== "domain-lists" ||
    values.length !== 1 ||
    values[0] === "" ||
    params.has("group")
  )
    return { kind: "invalid" };
  return { kind: "list", id: values[0] };
}

/** The view derives all detail fields and relationships from one validated snapshot. */
type Detail =
  { kind: "list"; list: RuleList } | { kind: "missing" } | { kind: "invalid" };

/** resolveDetail returns the current record or an explicit unavailable state after a snapshot change. */
function resolveDetail(selection: Selection, snapshot: Snapshot): Detail {
  if (selection.kind === "invalid") return selection;
  const list = snapshot.lists.find((item) => item.id === selection.id);
  return list ? { kind: "list", list } : { kind: "missing" };
}

/** Details presents the selected domain list and its configured group. */
@Component({
  selector: "hestia-details",
  imports: [BindingEditor, DomainLists],
  templateUrl: "./details.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Details {
  protected readonly groupName = groupName;
  readonly selection = input.required<Selection>();
  readonly snapshot = input.required<Snapshot>();
  protected readonly detail = computed(() =>
    resolveDetail(this.selection(), this.snapshot()),
  );
}
