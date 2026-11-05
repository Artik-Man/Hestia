import { Tooltip } from "primeng/tooltip";
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { RadioButton } from "primeng/radiobutton";
import { ToggleSwitch } from "primeng/toggleswitch";
import { ButtonDirective } from "primeng/button";
import { regionCodes } from "../../core/models/geo-policy";
import { CountryMapState } from "../../core/services/country-map-state.service";
import { SnapshotState } from "../../core/services/snapshot-state.service";

const names = new Intl.DisplayNames("ru", { type: "region" });

/** GeoScreen edits a local draft and saves the complete policy on explicit confirmation. */
@Component({
  selector: "hestia-geo",
  imports: [Tooltip, RadioButton, FormsModule, ToggleSwitch, ButtonDirective],
  templateUrl: "./geo.component.html",
  styleUrl: "./geo.component.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GeoScreen {
  protected readonly inventory = inject(SnapshotState);
  protected readonly state = inject(CountryMapState);
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
    const ids = Object.values(this.state.value()?.assignments ?? {});
    return [...new Set(ids.filter((id) => !this.groupIds().has(id)))];
  });
  protected readonly countries = regionCodes
    .map((code) => ({ code, label: names.of(code) ?? code }))
    .sort((a, b) => a.label.localeCompare(b.label, "ru"));

  /** Loads the current gateway map on entry, preserving a pending save across route changes. */
  constructor() {
    this.state.load();
  }

  /** toggle edits the requested routing mode while keeping all individual assignments. */
  protected toggle(enabled: boolean): void {
    const map = this.state.value();
    if (map && map.enabled !== enabled) this.state.edit({ ...map, enabled });
  }

  /** assign updates one country or every country to a current inventory group. */
  protected assign(group: string, country?: string): void {
    const map = this.state.value();
    if (
      !map ||
      !this.groupIds().has(group) ||
      (country && map.assignments[country] === group)
    )
      return;
    const assignments = country
      ? { ...map.assignments, [country]: group }
      : Object.fromEntries(regionCodes.map((code) => [code, group]));
    this.state.edit({ ...map, assignments });
  }
}
