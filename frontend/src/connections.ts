import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  signal,
  OnInit,
  inject,
} from "@angular/core";
import { HttpErrorResponse } from "@angular/common/http";
import { firstValueFrom } from "rxjs";
import { ProfileDraft } from "./profile-draft";
import { RouterLink } from "@angular/router";
import type { Group } from "./api/generated/model/group";
import type { AWGConnection } from "./api/generated/model/aWGConnection";
import { PanelService } from "./api/generated/api/panel.service";
import { ButtonDirective } from "primeng/button";

/** Connections lists configured exits in backend order with their priority within each group. */
@Component({
  selector: "hestia-connections",
  imports: [ButtonDirective, RouterLink, ProfileDraft],
  templateUrl: "./connections.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class Connections implements OnInit {
  protected readonly creating = signal(false);
  protected readonly editing = signal<AWGConnection | null>(null);
  protected readonly deleting = signal<string | null>(null);
  protected readonly awgConnections = signal<readonly AWGConnection[]>([]);
  protected readonly awgLoadError = signal("");
  private readonly panel = inject(PanelService);
  readonly groups = input.required<readonly Group[]>();
  protected readonly rows = computed(() =>
    this.groups().flatMap((group) =>
      group.exits.map((exit, index) => ({
        exit,
        group: group.id,
        priority: index + 1,
      })),
    ),
  );

  /** ngOnInit loads persisted public profile metadata without requesting private configuration data. */
  ngOnInit(): void {
    void this.loadAWGConnections();
  }

  /** loadAWGConnections reads the typed metadata endpoint and presents a safe unavailable state on failure. */
  private async loadAWGConnections(): Promise<void> {
    try {
      this.awgConnections.set(
        await firstValueFrom(this.panel.listAWGConnections()),
      );
      this.awgLoadError.set("");
    } catch (error: unknown) {
      this.awgConnections.set([]);
      this.awgLoadError.set(
        error instanceof HttpErrorResponse && error.status === 503
          ? "Управление WireGuard/AmneziaWG пока недоступно на этом шлюзе."
          : "Не удалось загрузить сохранённые профили.",
      );
    }
  }

  /** addSavedConnection updates the visible metadata after the API confirms profile storage. */
  protected addSavedConnection(connection: AWGConnection): void {
    this.awgConnections.update((connections) => [
      ...connections.filter((item) => item.id !== connection.id),
      connection,
    ]);
    this.creating.set(false);
    this.editing.set(null);
  }

  /** existingAWGIDs returns profile IDs for client-side duplicate checks in the create form. */
  protected existingAWGIDs(): string[] {
    return this.awgConnections().map((connection) => connection.id);
  }

  /** editConnection opens the importer with the selected public metadata and no stored secret material. */
  protected editConnection(connection: AWGConnection): void {
    this.editing.set(connection);
    this.creating.set(true);
  }

  /** closeEditor discards the selected file reference and closes the create/update panel. */
  protected closeEditor(): void {
    this.creating.set(false);
    this.editing.set(null);
  }

  /** deleteConnection removes one stored profile after explicit browser confirmation and refreshes public metadata. */
  protected async deleteConnection(connection: AWGConnection): Promise<void> {
    if (!window.confirm(`Удалить профиль «${connection.id}»?`)) return;
    this.deleting.set(connection.id);
    this.awgLoadError.set("");
    try {
      await firstValueFrom(this.panel.deleteAWGConnection(connection.id));
      this.awgConnections.update((items) =>
        items.filter((item) => item.id !== connection.id),
      );
    } catch (error: unknown) {
      this.awgLoadError.set(
        error instanceof HttpErrorResponse && error.status === 503
          ? "Шлюз не подтвердил удаление профиля."
          : "Не удалось удалить профиль.",
      );
    } finally {
      this.deleting.set(null);
    }
  }
}
