import { HttpErrorResponse } from "@angular/common/http";
import { computed, inject, Injectable, signal } from "@angular/core";
import { timeout } from "rxjs";
import { isCountryMap, regionCodes } from "../models/geo-policy";
import { Notifications } from "./notifications.service";
import { PanelService } from "./api/generated/api/panel.service";
import type { CountryMap } from "./api/generated/model/countryMap";

const countryMapSaveTimeoutMs = 4 * 60 * 1000;

/** CountryMapState serializes changes and reconciles uncertain writes against gateway storage. */
@Injectable({ providedIn: "root" })
export class CountryMapState {
  private readonly api = inject(PanelService);
  private readonly notifications = inject(Notifications);
  private readonly baseline = signal<CountryMap | null>(null);
  readonly value = signal<CountryMap | null>(null);
  readonly phase = signal<"idle" | "loading" | "saving" | "failed">("idle");
  readonly dirty = computed(() => {
    const saved = this.baseline(),
      draft = this.value();
    return (
      !!saved &&
      !!draft &&
      (saved.enabled !== draft.enabled ||
        regionCodes.some(
          (code) => saved.assignments[code] !== draft.assignments[code],
        ))
    );
  });

  /** load fetches the authoritative map, leaving edits unavailable on an incomplete or failed read. */
  load(): void {
    if (this.dirty() || this.phase() === "saving" || this.phase() === "loading")
      return;
    this.phase.set("loading");
    this.value.set(null);
    this.api
      .getCountryMap()
      .pipe(timeout(10000))
      .subscribe({
        next: (map) => {
          if (!isCountryMap(map)) {
            this.readFailed();
            return;
          }
          this.baseline.set(map);
          this.value.set(map);
          this.phase.set("idle");
        },
        error: () => this.readFailed(),
      });
  }

  /** readFailed offers a retry when the initial load cannot supply a complete map. */
  private readFailed(): void {
    this.notifications.show(
      "error",
      "Не удалось загрузить назначения со шлюза.",
    );
    this.phase.set("failed");
  }

  /** edit updates the in-memory draft while keeping its original compare-and-set version. */
  edit(candidate: CountryMap): void {
    if (this.phase() !== "idle") return;
    this.value.set(candidate);
  }

  /** save sends the whole draft once and waits for the bounded gateway transaction to finish. */
  save(): void {
    const candidate = this.value(),
      baseline = this.baseline();
    if (!candidate || !baseline || !this.dirty() || this.phase() !== "idle")
      return;
    this.phase.set("saving");
    this.api
      .updateCountryMap(candidate)
      .pipe(timeout(countryMapSaveTimeoutMs))
      .subscribe({
        next: (map) => {
          if (!isCountryMap(map)) {
            this.saveFailed();
            return;
          }
          this.baseline.set(map);
          this.value.set(map);
          this.notifications.show("success", "Маршруты по странам сохранены.");
          this.phase.set("idle");
        },
        error: (error: unknown) => {
          if (error instanceof HttpErrorResponse && error.status === 409)
            this.refreshConflict(baseline, candidate);
          else this.saveFailed();
        },
      });
  }

  /** saveFailed preserves the draft for an explicit version-checked retry. */
  private saveFailed(): void {
    this.notifications.show(
      "error",
      "Не удалось подтвердить сохранение маршрутов по странам. Повторите попытку.",
    );
    this.phase.set("idle");
  }

  /** refreshConflict keeps only local differences over the latest gateway policy for operator review. */
  private refreshConflict(baseline: CountryMap, draft: CountryMap): void {
    this.api
      .getCountryMap()
      .pipe(timeout(10000))
      .subscribe({
        next: (latest) => {
          if (!isCountryMap(latest)) {
            this.saveFailed();
            return;
          }
          const assignments = { ...latest.assignments };
          for (const code of regionCodes) {
            if (draft.assignments[code] !== baseline.assignments[code])
              assignments[code] = draft.assignments[code];
          }
          this.baseline.set(latest);
          this.value.set({
            ...latest,
            assignments,
            enabled:
              draft.enabled !== baseline.enabled
                ? draft.enabled
                : latest.enabled,
          });
          this.phase.set("idle");
          if (this.dirty())
            this.notifications.show(
              "warn",
              "Карта изменилась. Проверьте выбор и сохраните ещё раз.",
            );
          else
            this.notifications.show(
              "success",
              "Маршруты по странам сохранены.",
            );
        },
        error: () => this.saveFailed(),
      });
  }
}
