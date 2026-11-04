import { inject, Injectable } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import {
  catchError,
  exhaustMap,
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

/** SnapshotState serves both pages from one validated read and ignores refreshes while it is in flight. */
@Injectable({ providedIn: "root" })
export class SnapshotState {
  private readonly api = inject(PanelService);
  private readonly requests = new Subject<void>();
  readonly view = toSignal(
    this.requests.pipe(
      startWith(undefined),
      exhaustMap(() =>
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

  /** reload asks for the latest snapshot without interrupting a read already in progress. */
  reload(): void {
    this.requests.next();
  }
}
