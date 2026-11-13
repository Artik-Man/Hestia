import { isHysteria2Connection } from "../models/hysteria2-connection";
import type { Hysteria2Connection } from "./api/generated/model/hysteria2Connection";
import { HttpErrorResponse } from "@angular/common/http";
import { Injectable, computed, inject, signal } from "@angular/core";
import { PanelService } from "./api/generated/api/panel.service";
import type { AWGUnderlayCandidate } from "./api/generated/model/aWGUnderlayCandidate";
import { isUnderlayCandidate } from "../models/awg-connection";
import {
  EMPTY,
  Subject,
  catchError,
  defer,
  finalize,
  map,
  of,
  switchMap,
  timeout,
} from "rxjs";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";

/** ConnectionCatalog resolves immutable gateway IDs to the latest validated public display names. */
@Injectable({ providedIn: "root" })
export class ConnectionCatalog {
  private readonly api = inject(PanelService);
  private readonly requests = new Subject<void>();
  private readonly rows = signal<ReadonlyMap<string, AWGUnderlayCandidate>>(
    new Map(),
  );
  private readonly hysteriaRows = signal<
    ReadonlyMap<string, Hysteria2Connection>
  >(new Map());
  readonly hysteriaProfiles = this.hysteriaRows.asReadonly();
  readonly hysteriaFailed = signal(false);
  readonly entries = this.rows.asReadonly();
  readonly loading = signal(false);
  private readonly hysteriaLoading = signal(false);
  readonly reading = computed(() => this.loading() || this.hysteriaLoading());
  readonly failed = signal(false);

  /** Publishes only the latest validated catalog and records failed reads. */
  constructor() {
    this.requests
      .pipe(
        switchMap(() =>
          defer(() => {
            this.hysteriaLoading.set(true);
            return this.api.listHysteria2Connections();
          }).pipe(
            timeout(10000),
            map((rows: unknown) => {
              if (
                !Array.isArray(rows) ||
                !rows.every(isHysteria2Connection) ||
                new Set(rows.map((row) => row.id)).size !== rows.length
              )
                throw new Error("Invalid Hysteria 2 catalog");
              return new Map(rows.map((row) => [row.id, row]));
            }),
            catchError((error: unknown) =>
              error instanceof HttpErrorResponse && error.status === 409
                ? EMPTY
                : of(null),
            ),
            finalize(() => this.hysteriaLoading.set(false)),
          ),
        ),
        takeUntilDestroyed(),
      )
      .subscribe((rows) => {
        this.hysteriaLoading.set(false);
        this.hysteriaFailed.set(rows === null);
        if (rows !== null) this.hysteriaRows.set(rows);
      });
    this.requests
      .pipe(
        switchMap(() =>
          defer(() => {
            this.loading.set(true);
            return this.api.listAWGUnderlays();
          }).pipe(
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
            catchError((error: unknown) =>
              error instanceof HttpErrorResponse && error.status === 409
                ? EMPTY
                : of(null),
            ),
            finalize(() => this.loading.set(false)),
          ),
        ),
        takeUntilDestroyed(),
      )
      .subscribe((rows) => {
        this.loading.set(false);
        this.failed.set(rows === null);
        if (rows !== null) this.rows.set(rows);
      });
  }

  /** reload supersedes stale reads after a write, or skips unfinished reads during background polling. */
  reload(skipBusy = false): void {
    if (skipBusy && this.reading()) return;
    this.requests.next();
  }

  /** confirmEnabled applies the gateway-confirmed state before a fresh catalog supersedes it. */
  confirmEnabled(id: string, enabled: boolean): void {
    this.rows.update((rows) => {
      const entry = rows.get(id);
      return entry ? new Map(rows).set(id, { ...entry, enabled }) : rows;
    });
    this.hysteriaRows.update((rows) => {
      const entry = rows.get(id);
      return entry ? new Map(rows).set(id, { ...entry, enabled }) : rows;
    });
  }

  /** name resolves backend-provided labels and never exposes an unresolved routing identifier to the panel. */
  name(id: string): string {
    return (
      this.entries().get(id)?.name ??
      this.hysteriaRows().get(id)?.name ??
      "Подключение недоступно"
    );
  }

  /** describe resolves connection UUIDs embedded in route diagnostics to their public labels. */
  describe(message: string): string {
    return message.replace(
      /\b(?:g-)?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gu,
      (token) => (token.startsWith("g-") ? token : this.name(token)),
    );
  }
}
