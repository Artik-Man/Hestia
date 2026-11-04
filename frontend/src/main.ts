import { bootstrapApplication } from "@angular/platform-browser";
import { provideHttpClient } from "@angular/common/http";
import { providePrimeNG } from "primeng/config";
import { provideApi } from "./api/generated/provide-api";
import { provideRouter, withComponentInputBinding } from "@angular/router";
import { pages } from "./pages";
import { SnapshotScreen } from "./snapshot-screen";
import { Panel } from "./panel";

void bootstrapApplication(Panel, {
  providers: [
    provideRouter(
      [
        { path: "", pathMatch: "full", redirectTo: pages[0].path },
        ...pages.map((page) => ({
          path: page.path,
          component: SnapshotScreen,
          title: page.label + " · Гестия",
          data: { page },
        })),
      ],
      withComponentInputBinding(),
    ),
    provideApi(""),
    provideHttpClient(),
    providePrimeNG({ unstyled: true }),
  ],
});
