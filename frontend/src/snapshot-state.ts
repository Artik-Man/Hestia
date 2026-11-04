import { inject, Injectable } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import {
  catchError,
  switchMap,
  map,
  of,
  startWith,
  Subject,
  timeout,
} from "rxjs";
import { PanelService } from "./api/generated/api/panel.service";
import type { Snapshot } from "./api/generated/model/snapshot";
import { isSnapshot } from "./snapshot";

/** The shared state exposes only the current request or a successfully validated snapshot. */
type View =
  | { kind: "loading" }
  | { kind: "failed" }
  | { kind: "ready"; snapshot: Snapshot };

/** SnapshotState serves both pages from one validated read and replaces an obsolete read after a write. */
@Injectable({ providedIn: "root" })
export class SnapshotState {
  private readonly api = inject(PanelService);
  private readonly requests = new Subject<void>();
  readonly view = toSignal(
    this.requests.pipe(
      startWith(undefined),
      switchMap(() =>
        this.api.getGroupsAndRules().pipe(
          timeout(10000),
          map((value): View =>
            isSnapshot(value)
              ? { kind: "ready", snapshot: value }
              : { kind: "failed" },
          ),
          catchError(() => of<View>({ kind: "failed" })),
          startWith({ kind: "loading" } as const),
        ),
      ),
    ),
    { requireSync: true },
  );

  /** reload asks for the latest snapshot and supersedes an earlier read only when reconciling a write. */
  reload(afterWrite = false): void {
    if (afterWrite || this.view().kind !== "loading") this.requests.next();
  }
}
