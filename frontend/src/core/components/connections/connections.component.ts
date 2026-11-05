import { Tooltip } from "primeng/tooltip";
import { Toast } from "primeng/toast";
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  input,
  signal,
  OnInit,
  inject,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { firstValueFrom } from "rxjs";
import { SnapshotState } from "../../services/snapshot-state.service";
import { PhysicalConnections } from "../physical-connections/physical-connections.component";
import { ProfileDraft } from "../profile-draft/profile-draft.component";
import { ConnectionCatalog } from "../../services/connection-catalog.service";
import { InputText } from "primeng/inputtext";
import type { AWGUnderlayCandidate } from "../../services/api/generated/model/aWGUnderlayCandidate";
import type { Group } from "../../services/api/generated/model/group";
import type { AWGConnection } from "../../services/api/generated/model/aWGConnection";
import { PanelService } from "../../services/api/generated/api/panel.service";
import { Notifications } from "../../services/notifications.service";
import { Menu } from "primeng/menu";
import type { MenuItem } from "primeng/api";
import { ButtonDirective } from "primeng/button";

import {
  isAWGConnection,
  isUnderlayCandidate,
} from "../../models/awg-connection";

/** Connections merges gateway exits and saved profiles by stable routing ID. */
@Component({
  selector: "hestia-connections",
  imports: [
    Tooltip,
    Toast,
    ButtonDirective,
    Menu,
    InputText,
    ProfileDraft,
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
  protected readonly direct = signal<AWGUnderlayCandidate | null>(null);
  protected readonly directName = signal("");
  protected readonly renamePending = signal(false);
  protected readonly types = {
    direct: "Прямое подключение",
    wireguard: "WireGuard",
    amneziawg: "AmneziaWG",
  } as const;
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
  protected readonly awgConnections = signal<readonly AWGConnection[]>([]);
  private profileRead = 0;
  protected readonly loadingProfiles = signal(false);
  private readonly snapshot = inject(SnapshotState);
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
        ...profiles.keys(),
        ...this.catalog.entries().keys(),
      ]),
    ]
      .map((id) => {
        const profile = profiles.get(id);
        const exit = exits.get(id);
        const available = profile
          ? profile.status === "ready"
          : exit?.available;
        const entry = this.catalog.entries().get(id);
        return {
          id,
          profile,
          entry,
          name: profile?.name ?? this.catalog.name(id),
          available,
        };
      })
      .filter(
        (row) =>
          row.profile ||
          row.entry?.type === "wireguard" ||
          row.entry?.type === "amneziawg",
      );
  });

  /** Reports catalog read failures through the active page or modal toast. */
  constructor() {
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

  /** loadAWGConnections reads the typed metadata endpoint and presents a safe unavailable state on failure. */
  protected async loadAWGConnections(): Promise<void> {
    const read = ++this.profileRead;
    this.loadingProfiles.set(true);
    try {
      const records: unknown = await firstValueFrom(
        this.panel.listAWGConnections(),
      );
      if (read !== this.profileRead) return;
      if (
        !Array.isArray(records) ||
        !records.every(isAWGConnection) ||
        new Set(records.map((item) => item.id)).size !== records.length
      )
        throw new Error("Invalid connection list");
      this.awgConnections.set(records);
    } catch (error: unknown) {
      if (read !== this.profileRead) return;
      this.awgConnections.set([]);
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

  /** closeEditor discards the selected file reference and closes the create/update panel. */
  protected closeEditor(): void {
    this.creating.set(false);
    this.editing.set(null);
    this.editorTrigger?.focus();
    this.editorTrigger = null;
  }

  /** deleteConnection removes one stored profile after explicit browser confirmation and refreshes public metadata. */
  protected async deleteConnection(connection: AWGConnection): Promise<void> {
    if (!window.confirm(`Удалить профиль «${connection.name}»?`)) return;
    this.deleting.set(connection.id);
    try {
      await firstValueFrom(this.panel.deleteAWGConnection(connection.id));
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
