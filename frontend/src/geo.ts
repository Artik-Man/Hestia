import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  DestroyRef,
  inject,
  Injectable,
  signal,
} from "@angular/core";
import {
  initializeCountryMap,
  readCountryMap,
  regionCodes,
  type CountryMap,
} from "./geo-policy";
import { SnapshotState } from "./snapshot-state";

const names = new Intl.DisplayNames("ru", { type: "region" });
const storageKey = "hestia.country-map.draft.v1";

/** MapDraftState retains the origin's draft independently from inventory refreshes and default changes. */
@Injectable({ providedIn: "root" })
class MapDraftState {
  readonly value = signal<CountryMap | null>(null);
  readonly warning = signal("");

  /** Observes changes to the shared local draft made by another tab on this origin. */
  constructor() {
    const refresh = (event: StorageEvent): void => {
      if (event.key === storageKey && event.storageArea === localStorage) {
        const latest = readCountryMap(localStorage.getItem(storageKey));
        if (latest) {
          this.value.set(latest);
          this.warning.set("");
        }
      }
    };
    window.addEventListener("storage", refresh);
    inject(DestroyRef).onDestroy(() =>
      window.removeEventListener("storage", refresh),
    );
  }

  /** currentForEdit includes another tab's latest changes unless this draft is only in memory. */
  currentForEdit(): CountryMap | null {
    const current = this.value();
    if (!current || this.warning()) return current;
    try {
      return readCountryMap(localStorage.getItem(storageKey)) ?? current;
    } catch {
      return current;
    }
  }

  /** initialize loads a stored draft or captures the default once on first use. */
  initialize(defaultGroup: string): void {
    if (this.value()) return;
    try {
      const raw = localStorage.getItem(storageKey);
      const stored = readCountryMap(raw);
      if (stored) {
        this.value.set(stored);
        return;
      }
      if (raw !== null) {
        this.warning.set(
          "Сохранённый черновик повреждён. Не удалось загрузить назначения.",
        );
        return;
      }
    } catch {
      this.warning.set(
        "Хранилище браузера недоступно. Черновик доступен только до перезагрузки.",
      );
    }
    this.save(initializeCountryMap(defaultGroup));
  }

  /** save updates the local draft and reports when browser persistence fails. */
  save(map: CountryMap): void {
    this.value.set(map);
    try {
      localStorage.setItem(storageKey, JSON.stringify(map));
      this.warning.set("");
    } catch {
      this.warning.set(
        "Черновик доступен только до перезагрузки: браузер не сохранил изменения.",
      );
    }
  }
}

/** GeoScreen edits one explicit assignment per country without changing the gateway configuration. */
@Component({
  selector: "hestia-geo",
  templateUrl: "./geo.html",
  styleUrl: "./geo.css",
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
