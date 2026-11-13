import type { Hysteria2Connection } from "../../services/api/generated/model/hysteria2Connection";
import { Hysteria2Editor } from "../hysteria2-editor/hysteria2-editor.component";
import { Tooltip } from "primeng/tooltip";
import { Toast } from "primeng/toast";
import { FormsModule } from "@angular/forms";
import { ToggleSwitchModule } from "primeng/toggleswitch";
import {
  ChangeDetectionStrategy,
  DestroyRef,
  Component,
  computed,
  effect,
  input,
  signal,
  OnInit,
  inject,
  viewChild,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import {
  EMPTY,
  catchError,
  defer,
  exhaustMap,
  filter,
  firstValueFrom,
  map,
  merge,
  Observable,
  retry,
  take,
  throwError,
  timer,
  timeout,
} from "rxjs";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { SnapshotState } from "../../services/snapshot-state.service";
import { PhysicalConnections } from "../physical-connections/physical-connections.component";
import { ProfileDraft } from "../profile-draft/profile-draft.component";
import { ConnectionCatalog } from "../../services/connection-catalog.service";
import { InputText } from "primeng/inputtext";
import type { AWGUnderlayCandidate } from "../../services/api/generated/model/aWGUnderlayCandidate";
import type { Group } from "../../services/api/generated/model/group";
import type { AWGConnection } from "../../services/api/generated/model/aWGConnection";
import type { ConnectionEnabled } from "../../services/api/generated/model/connectionEnabled";
import { PanelService } from "../../services/api/generated/api/panel.service";
import { Notifications } from "../../services/notifications.service";
import { Menu } from "primeng/menu";
import type { MenuItem } from "primeng/api";
import { ButtonDirective } from "primeng/button";

import {
  isAWGConnection,
  isUnderlayCandidate,
  isUserSelectableUnderlay,
} from "../../models/awg-connection";

/** Connections merges gateway exits and saved profiles by stable routing ID, excluding platform ingress. */
@Component({
  selector: "hestia-connections",
  imports: [
    FormsModule,
    ToggleSwitchModule,
    Tooltip,
    Toast,
    ButtonDirective,
    Menu,
    InputText,
    ProfileDraft,
    Hysteria2Editor,
    PhysicalConnections,
  ],
  templateUrl: "./connections.component.html",
  styles: [
    ".profile-toolbar { flex-wrap: wrap; justify-content: space-between; gap: 12px; }",
    ".profile-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }",
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Connections implements OnInit {
  protected readonly revision = signal(0);
  protected readonly catalog = inject(ConnectionCatalog);
  protected readonly directTransports = computed(() => {
    const exits = new Map(
      this.groups().flatMap((group) =>
        group.exits.map((exit) => [exit.id, exit] as const),
      ),
    );
    return [...this.catalog.entries().values()]
      .filter(
        (entry) =>
          entry.type === "direct" && isUserSelectableUnderlay(entry.id, entry),
      )
      .map((entry) => ({
        ...entry,
        name: this.catalog.name(entry.id),
        purpose: this.directPurpose(entry.role),
        available: exits.get(entry.id)?.available,
      }))
      .sort((left, right) => left.name.localeCompare(right.name));
  });
  protected readonly direct = signal<AWGUnderlayCandidate | null>(null);
  protected readonly directName = signal("");
  protected readonly renamePending = signal(false);
  protected readonly types = {
    direct: "Прямое подключение",
    wireguard: "WireGuard",
    amneziawg: "AmneziaWG",
    hysteria2: "Hysteria 2",
  } as const;
  protected readonly hysteriaOpen = signal(false);
  protected readonly editingHysteria = signal<Hysteria2Connection | null>(null);
  protected readonly creating = signal(false);
  private editorTrigger: HTMLButtonElement | null = null;
  protected readonly connectionTypes: MenuItem[] = [
    {
      label: "WireGuard",
      command: () => {
        this.editing.set(null);
        this.creating.set(true);
      },
    },
    {
      label: "Hysteria 2",
      command: () => {
        this.editingHysteria.set(null);
        this.hysteriaOpen.set(true);
      },
    },
  ];

  /** openTypes opens the add menu and remembers the trigger for keyboard focus when the editor closes. */
  protected openTypes(
    menu: Menu,
    event: MouseEvent,
    trigger: HTMLButtonElement,
  ): void {
    this.editorTrigger = trigger;
    menu.toggle(event);
  }
  protected readonly editing = signal<AWGConnection | null>(null);
  protected readonly deleting = signal<string | null>(null);
  protected readonly changingEnabled = signal<ReadonlyMap<string, boolean>>(
    new Map(),
  );
  protected readonly awgConnections = signal<readonly AWGConnection[]>([]);
  private profileRead = 0;
  private profilesFailed = false;
  protected readonly loadingProfiles = signal(false);
  protected readonly snapshot = inject(SnapshotState);
  private readonly physical = viewChild(PhysicalConnections);
  private readonly destroyRef = inject(DestroyRef);
  private readonly panel = inject(PanelService);
  private readonly messages = inject(Notifications);
  readonly groups = input.required<readonly Group[]>();
  protected readonly rows = computed(() => {
    const exits = new Map(
      this.groups().flatMap((group) =>
        group.exits.map((exit) => [exit.id, exit] as const),
      ),
    );
    const profiles = new Map(
      this.awgConnections().map((profile) => [profile.id, profile]),
    );
    return [
      ...new Set([
        ...exits.keys(),
        ...this.catalog.hysteriaProfiles().keys(),
        ...profiles.keys(),
        ...this.catalog.entries().keys(),
      ]),
    ]
      .map((id) => {
        const profile = profiles.get(id);
        const hysteria = this.catalog.hysteriaProfiles().get(id);
        const exit = exits.get(id);
        const available = profile
          ? profile.status === "ready"
          : exit?.available;
        const entry = this.catalog.entries().get(id);
        return {
          id,
          profile,
          hysteria,
          entry,
          name: profile?.name ?? this.catalog.name(id),
          available,
          enabled:
            profile?.enabled ?? hysteria?.enabled ?? entry?.enabled ?? true,
        };
      })
      .filter(
        (row) =>
          isUserSelectableUnderlay(row.id, row.entry) &&
          (row.profile ||
            row.hysteria ||
            row.entry?.type === "wireguard" ||
            row.entry?.type === "amneziawg"),
      );
  });

  /** setEnabled pauses shared reads and reconciles the exact operation before releasing the switch. */
  protected async setEnabled(id: string, enabled: boolean): Promise<void> {
    if (
      typeof enabled !== "boolean" ||
      this.snapshot.connectionMutationPending() ||
      this.changingEnabled().has(id) ||
      this.deleting() === id
    )
      return;
    this.snapshot.connectionMutationPending.set(true);
    this.changingEnabled.update((pending) => new Map(pending).set(id, enabled));
    try {
      await this.waitForReaders();
      const result: unknown = await firstValueFrom(
        this.enabledOperation(id, enabled).pipe(
          takeUntilDestroyed(this.destroyRef),
        ),
      );
      if (
        !result ||
        typeof result !== "object" ||
        !("id" in result) ||
        result.id !== id ||
        !("enabled" in result) ||
        result.enabled !== enabled
      )
        throw new Error("Invalid connection state response");
      this.awgConnections.update((items) =>
        items.map((item) => (item.id === id ? { ...item, enabled } : item)),
      );
      this.catalog.confirmEnabled(id, enabled);
    } catch {
      if (this.destroyRef.destroyed) return;
      this.messages.show(
        "error",
        "Не удалось подтвердить состояние подключения. Обновляем состояние со шлюза.",
      );
    } finally {
      this.changingEnabled.update((pending) => {
        const next = new Map(pending);
        next.delete(id);
        return next;
      });
      this.snapshot.connectionMutationPending.set(false);
      if (!this.destroyRef.destroyed) this.refresh();
    }
  }

  /** enabledOperation retries brief lock conflicts and reconciles held HTTP responses through exact operation receipts. */
  private enabledOperation(
    id: string,
    enabled: boolean,
  ): Observable<ConnectionEnabled> {
    return defer(() => {
      const operationId = this.operationID();
      const write = this.panel.setConnectionEnabled(id, {
        enabled,
        operationId,
      });
      const receipt = timer(5000, 3000).pipe(
        exhaustMap(() =>
          this.panel.getConnectionEnabledOperation(operationId).pipe(
            timeout(10000),
            catchError(() => EMPTY),
          ),
        ),
        map((value: unknown) =>
          this.operationResult(value, operationId, id, enabled),
        ),
        filter((value): value is ConnectionEnabled => value !== null),
      );
      return merge(write, receipt).pipe(take(1));
    }).pipe(
      retry({
        count: 4,
        delay: (error: unknown) =>
          error instanceof HttpErrorResponse && error.status === 409
            ? timer(500)
            : throwError(() => error),
      }),
    );
  }

  /** operationID generates a UUIDv4 using the Web Crypto API available on trusted HTTP LAN pages. */
  private operationID(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (value) =>
      value.toString(16).padStart(2, "0"),
    ).join("");
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20),
    ].join("-");
  }

  /** operationResult accepts only the exact requested receipt and surfaces a confirmed rollback as a failure. */
  private operationResult(
    value: unknown,
    operationId: string,
    id: string,
    enabled: boolean,
  ): ConnectionEnabled | null {
    if (
      !value ||
      typeof value !== "object" ||
      !("operationId" in value) ||
      value.operationId !== operationId ||
      !("id" in value) ||
      value.id !== id ||
      !("enabled" in value) ||
      value.enabled !== enabled ||
      !("state" in value)
    )
      return null;
    const status = "status" in value ? value.status : undefined;
    if (value.state === "succeeded")
      return status === 200 ? { id, enabled } : null;
    if (value.state === "failed") {
      if (
        typeof status !== "number" ||
        !Number.isSafeInteger(status) ||
        status < 400 ||
        status > 599
      )
        return null;
      throw new HttpErrorResponse({ status });
    }
    return null;
  }

  /** waitForReaders drains existing shared-lock reads before starting the exclusive toggle transaction. */
  private async waitForReaders(): Promise<void> {
    await firstValueFrom(
      timer(0, 50).pipe(
        filter(
          () =>
            !this.snapshot.reading() &&
            !this.catalog.reading() &&
            !this.loadingProfiles() &&
            !this.physical()?.reading(),
        ),
        take(1),
        timeout(11000),
        takeUntilDestroyed(this.destroyRef),
      ),
    );
  }

  /** directPurpose translates the backend channel role into user-facing routing language. */
  protected directPurpose(role: AWGUnderlayCandidate["role"]): string {
    switch (role) {
      case "input":
        return "Входящий трафик Hestia";
      case "output":
        return "Прямой выход в интернет";
      default:
        return "Прямое подключение";
    }
  }

  /** Reports each catalog read failure through the active page or modal toast. */
  constructor() {
    timer(3000, 3000)
      .pipe(takeUntilDestroyed())
      .subscribe(() => {
        if (this.changingEnabled().size || this.deleting()) return;
        this.catalog.reload(true);
        if (!this.loadingProfiles()) void this.loadAWGConnections();
      });
    effect(() => {
      if (this.catalog.hysteriaFailed())
        this.messages.show(
          "error",
          "Не удалось загрузить подключения Hysteria 2.",
        );
    });
    effect(() => {
      if (this.catalog.failed())
        this.messages.show(
          "error",
          "Не удалось загрузить типы и названия подключений.",
        );
    });
  }

  /** refresh reads both the gateway snapshot and the latest saved tunnel states. */
  protected refresh(): void {
    this.revision.update((value) => value + 1);
    this.snapshot.reload(true, true);
    this.catalog.reload();
    void this.loadAWGConnections();
  }

  /** ngOnInit loads persisted public profile metadata without requesting private configuration data. */
  ngOnInit(): void {
    this.catalog.reload();
    void this.loadAWGConnections();
  }

  /** loadAWGConnections validates metadata, retains the last confirmed rows and announces an outage once. */
  protected async loadAWGConnections(): Promise<void> {
    const read = ++this.profileRead;
    this.loadingProfiles.set(true);
    try {
      const records: unknown = await firstValueFrom(
        this.panel
          .listAWGConnections()
          .pipe(timeout(10000), takeUntilDestroyed(this.destroyRef)),
      );
      if (this.destroyRef.destroyed || read !== this.profileRead) return;
      if (
        !Array.isArray(records) ||
        !records.every(isAWGConnection) ||
        new Set(records.map((item) => item.id)).size !== records.length
      )
        throw new Error("Invalid connection list");
      this.profilesFailed = false;
      this.awgConnections.set(records);
    } catch (error: unknown) {
      if (this.destroyRef.destroyed || read !== this.profileRead) return;
      if (error instanceof HttpErrorResponse && error.status === 409) return;
      if (this.profilesFailed) return;
      this.profilesFailed = true;
      this.messages.show(
        "error",
        error instanceof HttpErrorResponse && error.status === 503
          ? "Управление WireGuard/AmneziaWG пока недоступно на этом шлюзе."
          : "Не удалось загрузить сохранённые профили.",
      );
    } finally {
      if (read === this.profileRead) this.loadingProfiles.set(false);
    }
  }

  /** addSavedConnection updates the visible metadata after the API confirms profile storage. */
  protected addSavedConnection(connection: AWGConnection): void {
    this.awgConnections.update((connections) => [
      ...connections.filter((item) => item.id !== connection.id),
      connection,
    ]);
    this.closeEditor();
    this.catalog.reload();
    void this.loadAWGConnections();
    this.snapshot.reload(true, true);
  }

  /** openDirect opens the name-only editor using the stable direct interface record. */
  protected openDirect(
    dialog: HTMLDialogElement,
    entry: AWGUnderlayCandidate,
  ): void {
    this.direct.set(entry);
    this.directName.set(entry.name ?? entry.id);
    dialog.showModal();
  }

  /** saveDirect updates the display name of one interface and refreshes catalog labels on success. */
  protected async saveDirect(
    event: Event,
    dialog: HTMLDialogElement,
  ): Promise<void> {
    event.preventDefault();
    const target = this.direct();
    const name = this.directName().trim();
    if (!target || this.renamePending() || !name) return;
    this.renamePending.set(true);
    try {
      const result: unknown = await firstValueFrom(
        this.panel.renameDirectConnection(target.id, { name }),
      );
      if (
        !isUnderlayCandidate(result) ||
        result.type !== "direct" ||
        result.id !== target.id ||
        result.name !== name
      )
        throw new Error("Invalid rename response");
      this.catalog.reload();
      dialog.close();
      this.messages.show("success", "Название подключения сохранено.");
    } catch {
      this.messages.show("error", "Не удалось сохранить название подключения.");
    } finally {
      this.renamePending.set(false);
    }
  }

  /** editConnection opens the editor for the selected ID and records the button which opened it. */
  protected editConnection(
    connection: AWGConnection,
    trigger: HTMLButtonElement,
  ): void {
    this.editorTrigger = trigger;
    this.editing.set(connection);
    this.creating.set(true);
  }

  /** editHysteria restores public profile fields in a dedicated editor. */
  protected editHysteria(
    connection: Hysteria2Connection,
    trigger: HTMLButtonElement,
  ): void {
    this.editorTrigger = trigger;
    this.editingHysteria.set(connection);
    this.hysteriaOpen.set(true);
  }
  /** hysteriaSaved refreshes public catalogs and routes after a confirmed gateway mutation. */
  protected hysteriaSaved(): void {
    this.closeEditor();
    this.refresh();
    this.messages.show("success", "Подключение Hysteria 2 сохранено.");
  }

  /** closeEditor discards the selected file reference and closes the create/update panel. */
  protected closeEditor(): void {
    this.hysteriaOpen.set(false);
    this.editingHysteria.set(null);
    this.creating.set(false);
    this.editing.set(null);
    this.editorTrigger?.focus();
    this.editorTrigger = null;
  }

  /** deleteConnection removes one stored profile after explicit browser confirmation and refreshes public metadata. */
  protected async deleteConnection(
    connection: AWGConnection | Hysteria2Connection,
  ): Promise<void> {
    if (!window.confirm(`Удалить профиль «${connection.name}»?`)) return;
    this.deleting.set(connection.id);
    try {
      await firstValueFrom(
        "server" in connection
          ? this.panel.deleteHysteria2Connection(connection.id)
          : this.panel.deleteAWGConnection(connection.id),
      );
      this.awgConnections.update((items) =>
        items.filter((item) => item.id !== connection.id),
      );
      this.catalog.reload();
      void this.loadAWGConnections();
      this.snapshot.reload(true, true);
      this.messages.show(
        "success",
        `Подключение «${connection.name}» удалено.`,
      );
    } catch (error: unknown) {
      this.messages.show(
        "error",
        error instanceof HttpErrorResponse && error.status === 503
          ? "Шлюз не подтвердил удаление профиля."
          : "Не удалось удалить профиль.",
      );
    } finally {
      this.deleting.set(null);
    }
  }
}
