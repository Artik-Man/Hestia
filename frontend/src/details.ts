import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
} from "@angular/core";
import { type ParamMap, RouterLink } from "@angular/router";
import type { Exit } from "./api/generated/model/exit";
import type { Group } from "./api/generated/model/group";
import type { RuleList } from "./api/generated/model/ruleList";
import type { Snapshot } from "./api/generated/model/snapshot";
import type { Page } from "./pages";

/** A selection identifies exactly one supported object on its parent page. */
export type Selection =
  { kind: "group" | "list" | "exit"; id: string } | { kind: "invalid" };

/** readSelection returns null for the overview and rejects duplicate or misplaced detail selectors. */
export function readSelection(
  path: Page["path"],
  params: ParamMap,
): Selection | null {
  const keys = (["group", "list", "exit"] as const).filter((key) =>
    params.has(key),
  );
  if (!keys.length) return null;
  const key = keys[0];
  const values = params.getAll(key);
  if (
    keys.length !== 1 ||
    values.length !== 1 ||
    values[0] === "" ||
    (key === "exit") !== (path === "connections")
  )
    return { kind: "invalid" };
  return { kind: key, id: values[0] };
}

/** The view derives all detail fields and relationships from one validated snapshot. */
type Detail =
  | { kind: "group"; group: Group; lists: RuleList[] }
  | { kind: "list"; list: RuleList }
  | { kind: "exit"; exit: Exit; group: Group; priority: number }
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
    case "exit":
      for (const group of snapshot.groups) {
        const index = group.exits.findIndex((exit) => exit.id === selection.id);
        if (index >= 0)
          return {
            kind: "exit",
            exit: group.exits[index],
            group,
            priority: index + 1,
          };
      }
  }
  return { kind: "missing" };
}

/** Details presents the selected group, list or exit, including links to its configured relationships. */
@Component({
  selector: "hestia-details",
  imports: [RouterLink],
  templateUrl: "./details.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Details {
  readonly selection = input.required<Selection>();
  readonly snapshot = input.required<Snapshot>();
  protected readonly detail = computed(() =>
    resolveDetail(this.selection(), this.snapshot()),
  );
}
