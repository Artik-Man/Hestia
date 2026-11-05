import { Injectable, inject, signal } from "@angular/core";
import { PanelService } from "./api/generated/api/panel.service";
import type { AWGUnderlayCandidate } from "./api/generated/model/aWGUnderlayCandidate";
import { isUnderlayCandidate } from "../models/awg-connection";
import { Subject, catchError, map, of, switchMap, timeout } from "rxjs";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";

/** ConnectionCatalog resolves immutable gateway IDs to the latest validated public display names. */
@Injectable({ providedIn: "root" })
export class ConnectionCatalog {
  private readonly api = inject(PanelService);
  private readonly requests = new Subject<void>();
  private readonly rows = signal<ReadonlyMap<string, AWGUnderlayCandidate>>(
    new Map(),
  );
  readonly entries = this.rows.asReadonly();
  readonly loading = signal(false);
  readonly failed = signal(false);

  /** Publishes only the latest validated response and falls back to gateway IDs on a failed read. */
  constructor() {
    this.requests
      .pipe(
        switchMap(() =>
          this.api.listAWGUnderlays().pipe(
            timeout(10000),
            map((rows: unknown) => {
              if (
                !Array.isArray(rows) ||
                !rows.every(isUnderlayCandidate) ||
                new Set(rows.map((row) => row.id)).size !== rows.length
              )
                throw new Error("Invalid connection catalog");
              return new Map(rows.map((row) => [row.id, row]));
            }),
            catchError(() => of(null)),
          ),
        ),
        takeUntilDestroyed(),
      )
      .subscribe((rows) => {
        this.loading.set(false);
        this.failed.set(rows === null);
        this.rows.set(rows ?? new Map());
      });
  }

  /** reload supersedes stale catalog requests after navigation or a saved rename. */
  reload(): void {
    this.loading.set(true);
    this.failed.set(false);
    this.requests.next();
  }

  /** name preserves the gateway ID when an exit has no public label or the catalog is unavailable. */
  name(id: string): string {
    return this.entries().get(id)?.name ?? id;
  }
}
