import { Tooltip } from "primeng/tooltip";
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { RadioButton } from "primeng/radiobutton";
import { ToggleSwitch } from "primeng/toggleswitch";
import { ButtonDirective } from "primeng/button";
import {
  initializeCountryMap,
  regionCodes,
} from "../../core/models/geo-policy";
import { MapDraftState } from "../../core/services/map-draft-state.service";
import { SnapshotState } from "../../core/services/snapshot-state.service";

const names = new Intl.DisplayNames("ru", { type: "region" });

/** GeoScreen edits one explicit assignment per country without changing the gateway configuration. */
@Component({
  selector: "hestia-geo",
  imports: [Tooltip, RadioButton, FormsModule, ToggleSwitch, ButtonDirective],
  templateUrl: "./geo.component.html",
  styleUrl: "./geo.component.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GeoScreen {
  protected readonly inventory = inject(SnapshotState);
  protected readonly draft = inject(MapDraftState);
  protected readonly groups = computed(() => {
    const view = this.inventory.view();
    return view.kind === "ready" ? view.snapshot.groups : [];
  });
  protected readonly defaultGroup = computed(() =>
    this.groups().find((group) => group.isDefault),
  );
  protected readonly groupIds = computed(
    () => new Set(this.groups().map((group) => group.id)),
  );
  protected readonly missingGroups = computed(() => {
    const ids = Object.values(this.draft.value()?.assignments ?? {});
    return [...new Set(ids.filter((id) => !this.groupIds().has(id)))];
  });
  protected readonly countries = regionCodes
    .map((code) => ({ code, label: names.of(code) ?? code }))
    .sort((a, b) => a.label.localeCompare(b.label, "ru"));

  /** Creates the first draft once a validated inventory identifies the current default. */
  constructor() {
    effect(() => {
      const fallback = this.defaultGroup();
      if (fallback) this.draft.initialize(fallback.id);
    });
  }

  /** recreate replaces an unreadable local draft with a disabled map assigned to the current default. */
  protected recreate(): void {
    const fallback = this.defaultGroup();
    if (fallback && !this.draft.value())
      this.draft.save(initializeCountryMap(fallback.id));
  }

  /** toggle changes only the draft's routing switch and preserves every assignment. */
  protected toggle(enabled: boolean): void {
    const map = this.draft.currentForEdit();
    if (map) this.draft.save({ ...map, enabled });
  }

  /** assign updates one country or every country to a current inventory group. */
  protected assign(group: string, country?: string): void {
    const map = this.draft.currentForEdit();
    if (!map || !this.groupIds().has(group)) return;
    const assignments = country
      ? { ...map.assignments, [country]: group }
      : initializeCountryMap(group).assignments;
    this.draft.save({ ...map, assignments });
  }
}
