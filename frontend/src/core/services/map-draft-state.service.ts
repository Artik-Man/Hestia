import { DestroyRef, inject, Injectable, signal } from "@angular/core";
import {
  initializeCountryMap,
  readCountryMap,
  type CountryMap,
} from "../models/geo-policy";

const storageKey = "hestia.country-map.draft.v1";

/** MapDraftState retains the origin's draft independently from inventory refreshes and default changes. */
@Injectable({ providedIn: "root" })
export class MapDraftState {
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
