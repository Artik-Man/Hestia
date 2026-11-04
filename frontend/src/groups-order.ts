import type { Group } from "./api/generated/model/group";
import type { OrderedGroup } from "./api/generated/model/orderedGroup";

/** sourceOrder projects only the fields accepted by the reorder endpoint, ignoring availability. */
export function sourceOrder(groups: readonly Group[]): OrderedGroup[] {
  return groups.map((group) => ({
    id: group.id,
    exits: group.exits.map((exit) => exit.id),
  }));
}

/** matchesOrder checks the complete echoed group and exit order, including field types, before confirming a save. */
export function matchesOrder(
  value: unknown,
  expected: readonly OrderedGroup[],
): boolean {
  if (!Array.isArray(value) || value.length !== expected.length) return false;
  return value.every((item: unknown, index) => {
    const group = expected[index];
    return (
      typeof item === "object" &&
      item !== null &&
      "id" in item &&
      item.id === group.id &&
      "exits" in item &&
      Array.isArray(item.exits) &&
      item.exits.length === group.exits.length &&
      item.exits.every((exit: unknown, i: number) => exit === group.exits[i])
    );
  });
}

/** GroupDraft pairs an unsaved proposal with the gateway revision of the ordered IDs from which it was derived. */
export interface GroupDraft {
  baseline: OrderedGroup[];
  order: OrderedGroup[];
  changedSource: boolean;
}

/** reconcile preserves edits across refreshes and health changes; a conflicting source pins unsaved edits until the operator explicitly discards them. */
export function reconcile(
  actual: OrderedGroup[] | null,
  previous?: GroupDraft,
): GroupDraft {
  if (previous) {
    if (actual === null) return previous;
    if (matchesOrder(actual, previous.baseline))
      return previous.changedSource
        ? { ...previous, changedSource: false }
        : previous;
    if (
      !matchesOrder(previous.order, previous.baseline) &&
      !matchesOrder(actual, previous.order)
    )
      return { ...previous, changedSource: true };
  }
  const source = actual ?? [];
  return { baseline: source, order: source, changedSource: false };
}

/** moveTo returns a reordered copy; an out-of-range target or unchanged position leaves the input intact. */
export function moveTo<T>(items: T[], from: number, to: number): T[] {
  if (
    from === to ||
    from < 0 ||
    from >= items.length ||
    to < 0 ||
    to >= items.length
  )
    return items;
  const moved = [...items];
  moved.splice(to, 0, ...moved.splice(from, 1));
  return moved;
}
