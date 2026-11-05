import { DOCUMENT } from "@angular/common";
import { inject, Injectable } from "@angular/core";
import { MessageService } from "primeng/api";

/** Notifications publishes transient operation outcomes to the panel's shared PrimeNG Toast. */
@Injectable({ providedIn: "root" })
export class Notifications {
  private readonly document = inject(DOCUMENT);
  private readonly messages = inject(MessageService);

  /** show targets a dialog that stays open, the active native modal, or the page. */
  show(
    severity: "success" | "error" | "warn" | "info",
    summary: string,
    key?: string,
  ): void {
    // Native modal dialogs make every element outside their subtree inert.
    const dialog = this.document.querySelector("dialog:modal:has(p-toast)");
    this.messages.add({
      key: key ?? dialog?.id,
      severity,
      summary,
      styleClass: "gateway-toast-" + severity,
      contentStyleClass: "gateway-toast-content",
    });
  }
}
