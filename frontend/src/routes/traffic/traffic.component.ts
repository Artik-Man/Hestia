import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
  viewChild,
} from "@angular/core";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { FormControl, ReactiveFormsModule } from "@angular/forms";
import {
  Subscription,
  debounceTime,
  distinctUntilChanged,
  merge,
  timeout,
} from "rxjs";
import { ButtonDirective } from "primeng/button";
import { RefreshIcon } from "primeng/icons/refresh";
import { InputText } from "primeng/inputtext";
import { SelectModule } from "primeng/select";
import { Table, TableModule } from "primeng/table";
import type { TableLazyLoadEvent } from "primeng/types/table";
import { PanelService } from "../../core/services/api/generated/api/panel.service";
import type { TrafficEvent } from "../../core/services/api/generated/model/trafficEvent";
import { ConnectionCatalog } from "../../core/services/connection-catalog.service";
import { TrafficEvents } from "../../core/components/traffic-events/traffic-events.component";
import { TrafficSettingsDialog } from "../../core/components/traffic-settings/traffic-settings.component";
import { trafficLimits, validTrafficPage } from "./traffic-observations";

/** TrafficScreen keeps one bounded page of a stable server-side result set behind PrimeNG's virtual viewport. */
@Component({
  selector: "hestia-traffic",
  imports: [
    ButtonDirective,
    RefreshIcon,
    InputText,
    SelectModule,
    TableModule,
    ReactiveFormsModule,
    TrafficEvents,
    TrafficSettingsDialog,
  ],
  templateUrl: "./traffic.component.html",
  styleUrl: "../../styles/traffic-quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TrafficScreen {
  private readonly api = inject(PanelService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly catalog = inject(ConnectionCatalog);
  private readonly table = viewChild(Table);
  protected readonly query = new FormControl("", { nonNullable: true });
  protected readonly protocol = new FormControl<"TCP" | "UDP" | "">("", {
    nonNullable: true,
  });
  protected readonly output = new FormControl("", { nonNullable: true });
  protected readonly period = new FormControl(60, { nonNullable: true });
  protected readonly protocols = [
    { label: "Все протоколы", value: "" },
    { label: "TCP", value: "TCP" },
    { label: "UDP", value: "UDP" },
  ];
  protected readonly periods = [
    { label: "Последние 5 минут", value: 5 },
    { label: "Последний час", value: 60 },
    { label: "Последние 6 часов", value: 360 },
    { label: "Последние сутки", value: 1440 },
    { label: "Последние 3 суток", value: 4320 },
    { label: "Весь журнал", value: 0 },
  ];
  protected readonly rows = signal<(TrafficEvent | undefined)[]>([]);
  // Bound both the PrimeNG placeholder array and the physical height of the scrollbar.
  protected readonly windowSize = 10000;
  protected readonly windowStart = signal(0);
  protected readonly total = signal(0);
  protected readonly lost = signal(0);
  protected readonly sourceAvailable = signal(true);
  protected readonly lastInterruption = signal<string | undefined>(undefined);
  protected readonly error = signal(false);
  protected readonly busy = signal(false);
  protected readonly showSettings = signal(false);
  protected readonly selected = signal<TrafficEvent | null>(null);
  private readonly dateFormat = new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "medium",
  });
  private readonly connections = signal<string[]>([]);
  protected readonly outputs = computed(() => [
    { label: "Все выходы", value: "" },
    ...this.connections().map((id) => ({
      label: this.catalog.name(id),
      value: "connection:" + id,
    })),
    { label: "Заблокировано", value: "blocked" },
    { label: "Выход не подтверждён", value: "unconfirmed" },
  ]);
  private filters!: {
    query?: string;
    protocol?: "TCP" | "UDP";
    output?: string;
    from: string;
    until: string;
  };
  private snapshot?: string;
  private pageStart = 0;
  private pageEnd = 0;
  private request?: Subscription;

  /** Starts an initial snapshot and replaces it whenever the operator changes the effective filters. */
  constructor() {
    this.catalog.reload();
    merge(
      this.query.valueChanges.pipe(debounceTime(200), distinctUntilChanged()),
      this.protocol.valueChanges,
      this.output.valueChanges,
      this.period.valueChanges,
    )
      .pipe(takeUntilDestroyed())
      .subscribe(() => this.refresh());
    this.refresh();
  }

  /** refresh anchors a new time window at the present and resets scrolling without changing any filter. */
  protected refresh(): void {
    this.request?.unsubscribe();
    const now = Date.now();
    this.filters = {
      query: this.query.value.trim() || undefined,
      protocol: this.protocol.value || undefined,
      output: this.output.value || undefined,
      until: new Date(now).toISOString(),
      from: new Date(
        this.period.value ? now - this.period.value * 60000 : 0,
      ).toISOString(),
    };
    this.snapshot = undefined;
    this.windowStart.set(0);
    this.total.set(0);
    this.pageStart = 0;
    this.pageEnd = 0;
    this.rows.set([]);
    this.selected.set(null);
    this.table()?.scrollToVirtualIndex(0);
    this.read(0, trafficLimits.page);
  }

  /** viewport loads a contiguous page around the visible range, dropping previously loaded rows outside it. */
  protected viewport(event: TableLazyLoadEvent): void {
    if (!this.snapshot || !this.rows().length) return;
    const first = this.windowStart() + Math.max(0, event.first ?? 0);
    const last = Math.min(
      this.windowStart() + this.rows().length,
      first + Math.max(1, event.rows ?? 1),
    );
    if (first >= this.pageStart && last <= this.pageEnd) return;
    const start = Math.max(
      this.windowStart(),
      Math.min(
        first - 100,
        this.windowStart() + this.rows().length - trafficLimits.page,
      ),
    );
    this.read(start, trafficLimits.page);
  }

  /** moveWindow opens the next or previous scrollable range without changing the time or snapshot. */
  protected moveWindow(offset: number): void {
    if (offset < 0 || offset >= this.total()) return;
    this.windowStart.set(offset);
    this.rows.set([]);
    this.table()?.scrollToVirtualIndex(0);
    this.read(offset, trafficLimits.page);
  }

  /** read cancels superseded requests and publishes only validated rows belonging to the active snapshot. */
  private read(offset: number, limit: number): void {
    this.request?.unsubscribe();
    this.busy.set(true);
    this.error.set(false);
    this.pageStart = offset;
    this.pageEnd = offset + limit;
    const snapshot = this.snapshot;
    this.request = this.api
      .getTraffic(
        this.filters.query,
        this.filters.protocol,
        this.filters.output,
        this.filters.from,
        this.filters.until,
        offset,
        limit,
        snapshot,
      )
      .pipe(timeout(15000), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (value: unknown) => {
          this.busy.set(false);
          if (!validTrafficPage(value, offset, limit, snapshot)) {
            this.fail();
            return;
          }
          this.snapshot = value.snapshot;
          this.total.set(value.total);
          if (this.windowStart() > 0 && this.windowStart() >= value.total) {
            this.windowStart.set(0);
            this.table()?.scrollToVirtualIndex(0);
            this.read(0, trafficLimits.page);
            return;
          }
          this.pageEnd = offset + value.events.length;
          const placeholders = new Array<TrafficEvent | undefined>(
            Math.min(this.windowSize, value.total - this.windowStart()),
          );
          value.events.forEach((row, index) => {
            placeholders[offset - this.windowStart() + index] = row;
          });
          this.rows.set(placeholders);
          this.lost.set(value.lost);
          this.sourceAvailable.set(value.sourceAvailable);
          this.lastInterruption.set(value.lastInterruption);
          const chosen = this.output.value;
          this.connections.set(
            chosen.startsWith("connection:")
              ? [
                  ...new Set([
                    ...value.outputs,
                    chosen.slice("connection:".length),
                  ]),
                ]
              : value.outputs,
          );
        },
        error: () => this.fail(),
      });
  }

  /** fail leaves a visible retry path without reporting a read failure as an empty journal. */
  private fail(): void {
    this.busy.set(false);
    this.error.set(true);
    this.pageStart = 0;
    this.pageEnd = 0;
  }

  /** timestamp formats a validated gateway timestamp in the operator’s local time zone. */
  protected timestamp(value: string): string {
    return this.dateFormat.format(Date.parse(value));
  }

  /** exitName separates the actual connection from blocked and unconfirmed routing decisions. */
  protected exitName(row: TrafficEvent): string {
    if (row.kind === "observed") return this.catalog.name(row.connection ?? "");
    if (row.kind === "blocked") return "Заблокировано";
    return row.connection
      ? this.catalog.name(row.connection) + " · выход не подтверждён"
      : "Выход не подтверждён";
  }
}
