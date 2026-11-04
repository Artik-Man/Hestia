import { ChangeDetectionStrategy, Component, inject } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { RouterLink, RouterLinkActive, RouterOutlet } from "@angular/router";
import { catchError, map, of, timeout } from "rxjs";
import { PanelService } from "./api/generated/api/panel.service";
import { pages } from "./pages";

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

/** Panel keeps internal navigation available even when the optional Grafana configuration fails. */
@Component({
  selector: "hestia-panel",
  imports: [RouterLink, RouterLinkActive, RouterOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: "./panel.html",
})
export class Panel {
  protected readonly pages = pages;
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
