import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  inject,
  signal,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { ButtonDirective } from "primeng/button";
import { KeyValuePipe } from "@angular/common";
import { TableModule } from "primeng/table";
import { Subscription, timer, timeout } from "rxjs";
import { PanelService } from "./api/generated/api/panel.service";
import type { QualityReport } from "./api/generated/model/qualityReport";
import { ConnectionCatalog } from "./connection-catalog";
import { isQualityReport, qualityLabel } from "./quality-observations";
import { Notifications } from "./notifications";
import { QualityEditor } from "./quality-report";

/** QualityScreen displays the gateway's ordered group rows and refreshes without disturbing edits. */
@Component({
  selector: "hestia-quality",
  imports: [ButtonDirective, QualityEditor, TableModule, KeyValuePipe],
  templateUrl: "./quality.html",
  styleUrl: "./quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class QualityScreen {
  private readonly api = inject(PanelService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly notifications = inject(Notifications);
  protected readonly catalog = inject(ConnectionCatalog);
  protected readonly report = signal<QualityReport | null>(null);
  protected readonly failed = signal(false);
  protected readonly label = qualityLabel;
  protected readonly busy = signal(false);
  private request?: Subscription;
  protected readonly numberFormat = new Intl.NumberFormat("ru-RU", {
    maximumFractionDigits: 2,
  });
  protected readonly dateFormat = new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "medium",
  });

  /** Starts lightweight polling while this route is visible and cancels outstanding reads on navigation. */
  constructor() {
    this.catalog.reload();
    timer(0, 15000)
      .pipe(takeUntilDestroyed())
      .subscribe(() => {
        if (!this.busy()) this.reload();
      });
  }

  /** reload supersedes the previous read and accepts only a valid gateway report. */
  protected reload(): void {
    this.request?.unsubscribe();
    this.busy.set(true);
    this.request = this.api
      .getQuality()
      .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (body: unknown) => {
          this.busy.set(false);
          const valid = isQualityReport(body);
          if (valid) {
            this.report.set(body);
            this.failed.set(false);
          } else this.readFailure();
        },
        error: () => {
          this.busy.set(false);
          this.readFailure();
        },
      });
  }

  /** readFailure announces the first failed refresh while keeping the last report available for comparison. */
  private readFailure(): void {
    if (!this.failed())
      this.notifications.show("error", "Не удалось обновить качество связи.");
    this.failed.set(true);
  }

  /** timestamp formats the gateway snapshot time for the operator's local timezone. */
  protected timestamp(value: string): string {
    return this.dateFormat.format(new Date(value));
  }

  /** hasActive checks whether the controller confirmed any active exit in this group's snapshot. */
  protected hasActive(group: QualityReport["groups"][number]): boolean {
    return group.connections.some((row) => row.active);
  }

  /** result resolves a table column by protocol even when the gateway changes array order. */
  protected result(
    row: QualityReport["groups"][number]["connections"][number],
    protocol: string,
  ) {
    return row.result.checks.find((check) => check.protocol === protocol);
  }
}
