import {
  ChangeDetectionStrategy,
  Component,
  inject,
  signal,
} from "@angular/core";
import { Tooltip } from "primeng/tooltip";
import { computed } from "@angular/core";
import { ButtonDirective } from "primeng/button";
import { toSignal } from "@angular/core/rxjs-interop";
import { RouterLink, RouterLinkActive } from "@angular/router";
import { catchError, map, of, timeout } from "rxjs";
import { PanelService } from "../../services/api/generated/api/panel.service";
import { navigationPages } from "../../../routes/pages";

/** grafanaLink accepts a configured absolute HTTPS URL and rejects malformed navigation responses. */
function grafanaLink(value: unknown): string | null {
  if (
    typeof value !== "object" ||
    value === null ||
    !("grafanaUrl" in value) ||
    typeof value.grafanaUrl !== "string" ||
    !/^https:\/\/[^/?#]/i.test(value.grafanaUrl) ||
    /[\\\s]/u.test(value.grafanaUrl)
  )
    return null;
  try {
    const url = new URL(value.grafanaUrl);
    return url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      url.port !== "0"
      ? url.href
      : null;
  } catch {
    return null;
  }
}

/** Menu keeps internal navigation available even when the optional Grafana configuration fails. */
@Component({
  selector: "hestia-menu",
  imports: [RouterLink, RouterLinkActive, Tooltip, ButtonDirective],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: "./menu.component.html",
  styleUrl: "./menu.component.css",
})
export class Menu {
  protected readonly expanded = signal(false);
  protected readonly toggleLabel = computed(() =>
    this.expanded() ? "Свернуть меню" : "Развернуть меню",
  );

  /** closeOnPhone dismisses the overlay after choosing a destination on narrow screens. */
  protected closeOnPhone(): void {
    if (window.matchMedia("(max-width: 600px)").matches)
      this.expanded.set(false);
  }

  protected readonly icons = {
    groups: "M4 4h6v6H4z M14 4h6v6h-6z M4 14h6v6H4z M14 14h6v6h-6z",
    "domain-lists": "M4 5h16 M4 12h16 M4 19h16",
    connections: "M3 8h6v8H3z M15 8h6v8h-6z M9 12h6",
    "country-map":
      "M12 2a10 10 0 1 0 0 20 10 10 0 1 0 0-20z M2 12h20 M12 2q-9 10 0 20q9-10 0-20z",
    traffic: "M3 7h17l-4-4 M21 17H4l4 4",
    quality: "M2 13h5l3-8 4 14 3-6h5",
    dns: "M3 4h18v6H3z M3 14h18v6H3z M6 7h2 M6 17h2",
  };
  protected readonly pages = navigationPages;
  protected readonly grafanaUrl = toSignal(
    inject(PanelService)
      .getNavigation()
      .pipe(
        timeout(10000),
        map(grafanaLink),
        catchError(() => of(null)),
      ),
    { initialValue: null },
  );
}
