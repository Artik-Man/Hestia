import { ChangeDetectionStrategy, Component } from "@angular/core";
import { RouterOutlet } from "@angular/router";
import { Toast } from "primeng/toast";
import { version } from "../../../../package.json";
import { Menu } from "../menu/menu.component";

declare const HESTIA_BUILD_TARGET: "" | "vm" | "keenetic";

/** Panel hosts gateway notifications, navigation and the active route. */
@Component({
  selector: "hestia-panel",
  imports: [Menu, RouterOutlet, Toast],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: "./panel.component.html",
})
export class Panel {
  protected readonly version = HESTIA_BUILD_TARGET
    ? `${version}-${HESTIA_BUILD_TARGET}`
    : version;
}
