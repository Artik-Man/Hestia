import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  linkedSignal,
} from "@angular/core";
import type { RuleList } from "./api/generated/model/ruleList";

/** validMask accepts the same wildcard suffix and ASCII DNS labels as the routing model. */
function validMask(mask: string): boolean {
  if (!mask.startsWith("*.")) return false;
  const suffix = mask.slice(2).replace(/\.$/, "");
  return (
    suffix.length > 0 &&
    suffix.length <= 253 &&
    suffix
      .split(".")
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
  );
}

/** MasksDraft validates one mask per line in memory without changing the displayed gateway list. */
@Component({
  selector: "hestia-masks-draft",
  templateUrl: "./masks-draft.html",
  styleUrl: "./editor.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MasksDraft {
  readonly list = input.required<RuleList>();
  protected readonly text = linkedSignal(() => this.list().masks.join("\n"));
  protected readonly masks = computed(() =>
    this.text()
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean),
  );
  protected readonly invalid = computed(() =>
    this.masks().filter((mask) => !validMask(mask)),
  );
}
