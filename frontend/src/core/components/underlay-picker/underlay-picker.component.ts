import {
  ChangeDetectionStrategy,
  Component,
  computed,
  inject,
  input,
  model,
  signal,
} from "@angular/core";
import { Tooltip } from "primeng/tooltip";
import { isUserSelectableUnderlay } from "../../models/awg-connection";
import { ConnectionCatalog } from "../../services/connection-catalog.service";

/** UnderlayPicker edits an ordered list of candidate connections, restoring automatic routing when the list is empty. */
@Component({
  selector: "hestia-underlay-picker",
  imports: [Tooltip],
  templateUrl: "./underlay-picker.component.html",
  styleUrl: "./underlay-picker.component.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UnderlayPicker {
  readonly target = input<string | null>(null);
  readonly underlays = model.required<string[]>();
  protected readonly choicesOpen = signal(false);
  protected readonly catalog = inject(ConnectionCatalog);
  protected readonly loadingCandidates = this.catalog.loading;
  protected readonly underlayChoices = computed(() => {
    const candidates = this.catalog.entries();
    return [...new Set([...this.underlays(), ...candidates.keys()])].filter(
      (id) =>
        id !== this.target() &&
        isUserSelectableUnderlay(id, candidates.get(id)),
    );
  });
  protected readonly underlaySummary = computed(() => {
    const candidates = this.catalog.entries();
    const selected = this.underlays();
    const visible = selected.filter((id) =>
      isUserSelectableUnderlay(id, candidates.get(id)),
    );
    return (
      visible.map((id) => this.catalog.name(id)).join(" → ") ||
      (selected.some((id) => !isUserSelectableUnderlay(id, candidates.get(id)))
        ? "Системный маршрут"
        : "")
    );
  });

  /** toggleChoices refreshes the available transports whenever the chooser opens. */
  protected toggleChoices(): void {
    this.choicesOpen.update((open) => !open);
    if (this.choicesOpen()) this.catalog.reload();
  }

  private dragging: string | null = null;

  /** toggleUnderlay appends a newly enabled transport or removes it while retaining the other priorities. */
  protected toggleUnderlay(id: string): void {
    if (this.underlays().length >= 64 && !this.underlays().includes(id)) return;
    this.underlays.update((ids) =>
      ids.includes(id) ? ids.filter((item) => item !== id) : [...ids, id],
    );
  }

  /** moveUnderlay moves one enabled transport to its requested rank without changing the selected set. */
  protected moveUnderlay(id: string, to: number): void {
    const ids = [...this.underlays()];
    const from = ids.indexOf(id);
    if (from < 0 || to < 0 || to >= ids.length || from === to) return;
    ids.splice(from, 1);
    ids.splice(to, 0, id);
    this.underlays.set(ids);
  }

  /** startUnderlayDrag identifies a selected transport for a local reorder. */
  protected startUnderlayDrag(event: DragEvent, id: string): void {
    this.dragging = id;
    event.dataTransfer?.setData("text/plain", id);
  }

  /** dropUnderlay applies only an internal drag onto another selected transport. */
  protected dropUnderlay(event: DragEvent, id: string): void {
    event.preventDefault();
    if (this.dragging)
      this.moveUnderlay(this.dragging, this.underlays().indexOf(id));
    this.dragging = null;
  }

  /** endUnderlayDrag clears the drag identity after cancellation or a completed drop. */
  protected endUnderlayDrag(): void {
    this.dragging = null;
  }
}
