import { groupName } from "./snapshot";
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  OnInit,
} from "@angular/core";
import { ConnectionCatalog } from "./connection-catalog";
import { BindingEditor } from "./binding";
import { DomainLists } from "./domain-lists";
import { type ParamMap, RouterLink } from "@angular/router";
import type { Group } from "./api/generated/model/group";
import type { RuleList } from "./api/generated/model/ruleList";
import type { Snapshot } from "./api/generated/model/snapshot";
import type { Page } from "./pages";

/** A selection identifies exactly one supported object on its parent page. */
export type Selection =
  { kind: "group" | "list"; id: string } | { kind: "invalid" };

/** readSelection returns null for the overview and rejects duplicate or misplaced detail selectors. */
export function readSelection(
  path: Page["path"],
  params: ParamMap,
): Selection | null {
  const keys = (["group", "list"] as const).filter((key) => params.has(key));
  if (!keys.length) return null;
  const key = keys[0];
  const values = params.getAll(key);
  if (
    keys.length !== 1 ||
    values.length !== 1 ||
    values[0] === "" ||
    path !== ({ group: "groups", list: "domain-lists" } as const)[key]
  )
    return { kind: "invalid" };
  return { kind: key, id: values[0] };
}

/** The view derives all detail fields and relationships from one validated snapshot. */
type Detail =
  | { kind: "group"; group: Group; lists: RuleList[] }
  | { kind: "list"; list: RuleList }
  | { kind: "missing" }
  | { kind: "invalid" };

/** resolveDetail returns the current record or an explicit unavailable state after a snapshot change. */
function resolveDetail(selection: Selection, snapshot: Snapshot): Detail {
  switch (selection.kind) {
    case "invalid":
      return selection;
    case "group": {
      const group = snapshot.groups.find((item) => item.id === selection.id);
      if (group)
        return {
          kind: "group",
          group,
          lists: snapshot.lists.filter((list) => list.group === group.id),
        };
      break;
    }
    case "list": {
      const list = snapshot.lists.find((item) => item.id === selection.id);
      if (list) return { kind: "list", list };
      break;
    }
  }
  return { kind: "missing" };
}

/** Details presents the selected group or list, including links to its configured relationships. */
@Component({
  selector: "hestia-details",
  imports: [RouterLink, BindingEditor, DomainLists],
  templateUrl: "./details.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Details implements OnInit {
  protected readonly groupName = groupName;
  protected readonly catalog = inject(ConnectionCatalog);
  readonly selection = input.required<Selection>();
  readonly snapshot = input.required<Snapshot>();
  protected readonly detail = computed(() =>
    resolveDetail(this.selection(), this.snapshot()),
  );
  /** ngOnInit refreshes connection labels for group membership rows. */
  ngOnInit(): void {
    if (this.selection().kind === "group") this.catalog.reload();
  }
}
