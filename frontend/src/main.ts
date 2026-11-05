import { inject } from "@angular/core";
import { bootstrapApplication } from "@angular/platform-browser";
import { provideHttpClient } from "@angular/common/http";
import { MessageService } from "primeng/api";
import Aura from "@primeuix/themes/aura";
import { providePrimeNG } from "primeng/config";
import { provideApi } from "./core/services/api/generated/provide-api";
import {
  Router,
  provideRouter,
  withComponentInputBinding,
  withHashLocation,
} from "@angular/router";
import { featurePages, pages } from "./routes/pages";
import { SnapshotScreen } from "./routes/snapshot-screen/snapshot-screen.component";
import { Panel } from "./core/components/panel/panel.component";

// Preserve bookmarks created before the panel used fragment URLs for local pages.
if (
  !location.hash &&
  ["/groups-and-rules", "/connections"].includes(location.pathname)
) {
  history.replaceState(
    history.state,
    "",
    "/#" + location.pathname + location.search,
  );
}

void bootstrapApplication(Panel, {
  providers: [
    provideRouter(
      [
        { path: "", pathMatch: "full", redirectTo: pages[0].path },
        {
          path: "groups-and-rules",
          pathMatch: "full",
          redirectTo: ({ queryParams, fragment }) =>
            inject(Router).createUrlTree(
              [
                Object.hasOwn(queryParams, "list")
                  ? "/domain-lists"
                  : "/groups",
              ],
              { queryParams, fragment: fragment ?? undefined },
            ),
        },
        ...pages.map((page) => ({
          path: page.path,
          component: SnapshotScreen,
          title: page.label + " · Hestia",
          data: { page },
        })),
        ...featurePages.map(({ path, label, loadComponent }) => ({
          path,
          title: label + " · Hestia",
          loadComponent,
        })),
        { path: "**", redirectTo: pages[0].path },
      ],
      withHashLocation(),
      withComponentInputBinding(),
    ),
    provideApi(""),
    provideHttpClient(),
    MessageService,
    providePrimeNG({
      theme: { preset: Aura, options: { darkModeSelector: false } },
      translation: { aria: { close: "Закрыть" } },
    }),
  ],
});
