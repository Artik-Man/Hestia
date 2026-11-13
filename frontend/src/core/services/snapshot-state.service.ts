import { inject, Injectable, signal } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import {
  catchError,
  defer,
  finalize,
  switchMap,
  map,
  of,
  startWith,
  Subject,
  timeout,
  tap,
} from "rxjs";
import { Notifications } from "./notifications.service";
import { PanelService } from "./api/generated/api/panel.service";
import type { Snapshot } from "./api/generated/model/snapshot";
import { isSnapshot } from "../models/snapshot";

/** The shared state exposes only the current request or a successfully validated snapshot. */
type View =
  | { kind: "loading" }
  | { kind: "failed" }
  | { kind: "ready"; snapshot: Snapshot };

/** SnapshotState serves both pages from one validated read and replaces an obsolete read after a write. */
@Injectable({ providedIn: "root" })
export class SnapshotState {
  private readonly api = inject(PanelService);
  private readonly notifications = inject(Notifications);
  private readonly requests = new Subject<boolean>();
  readonly reading = signal(false);
  private lastGood?: Snapshot;
  private readFailed = false;
  readonly view = toSignal(
    this.requests.pipe(
      startWith(false),
      switchMap((keepCurrent) => {
        const read = defer(() => {
          this.reading.set(true);
          return this.api.getGroupsAndRules();
        }).pipe(
          finalize(() => this.reading.set(false)),
          timeout(10000),
          map((value): View =>
            isSnapshot(value)
              ? { kind: "ready", snapshot: value }
              : { kind: "failed" },
          ),
          catchError(() => of<View>({ kind: "failed" })),
          tap((view) => {
            if (view.kind === "ready") this.lastGood = view.snapshot;
            if (view.kind === "failed" && !this.readFailed)
              this.notifications.show(
                "error",
                "Не удалось загрузить конфигурацию шлюза.",
              );
            this.readFailed = view.kind === "failed";
          }),
          map((view): View =>
            view.kind === "failed" && keepCurrent && this.lastGood
              ? { kind: "ready", snapshot: this.lastGood }
              : view,
          ),
        );
        return keepCurrent
          ? read
          : read.pipe(startWith({ kind: "loading" } as const));
      }),
    ),
    { requireSync: true },
  );

  /** reload asks for the latest snapshot and supersedes an earlier read only when reconciling a write. */
  reload(afterWrite = false, keepCurrent = false): void {
    if (afterWrite || (!this.reading() && this.view().kind !== "loading"))
      this.requests.next(keepCurrent && this.view().kind === "ready");
  }
}
