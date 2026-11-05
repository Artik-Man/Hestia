import { inject } from "@angular/core";
import { bootstrapApplication } from "@angular/platform-browser";
import { provideHttpClient } from "@angular/common/http";
import { MessageService } from "primeng/api";
import { definePreset } from "@primeuix/themes";
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
      theme: {
        preset: definePreset(Aura, {
          semantic: {
            primary: {
              50: "{sky.50}",
              100: "{sky.100}",
              200: "{sky.200}",
              300: "{sky.300}",
              400: "{sky.400}",
              500: "{sky.500}",
              600: "{sky.600}",
              700: "{sky.700}",
              800: "{sky.800}",
              900: "{sky.900}",
              950: "{sky.950}",
            },
            colorScheme: {
              dark: {
                highlight: {
                  background: "var(--ui-selected)",
                  focusBackground: "var(--ui-selected)",
                  color: "var(--ui-accent)",
                  focusColor: "var(--ui-onaction)",
                },
                list: {
                  option: {
                    focusBackground: "var(--ui-raised)",
                    focusColor: "var(--ui-text)",
                  },
                },
                formField: {
                  background: "var(--ui-panel)",
                  borderColor: "var(--ui-border)",
                  focusBorderColor: "var(--ui-accent)",
                },
                overlay: {
                  select: {
                    background: "var(--ui-panel)",
                    borderColor: "var(--ui-border)",
                    color: "var(--ui-text)",
                  },
                },
                primary: {
                  color: "var(--ui-accent)",
                  hoverColor: "#88d8ff",
                  activeColor: "#b6e7ff",
                },
              },
            },
          },
        }),
        options: { darkModeSelector: ".hestia-dark" },
      },
      translation: { aria: { close: "Закрыть" } },
    }),
  ],
});
