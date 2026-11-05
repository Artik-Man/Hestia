import { Tooltip } from "primeng/tooltip";
import { DatePipe } from "@angular/common";
import {
  ChangeDetectionStrategy,
  Component,
  inject,
  input,
  output,
  signal,
} from "@angular/core";
import { InputText } from "primeng/inputtext";
import { ButtonDirective } from "primeng/button";
import { Notifications } from "../../services/notifications.service";
import {
  canonicalDomain,
  type CheckedSnapshot,
  type CheckedWarm,
} from "../../../routes/dns/dns-validation";

export type DnsList = "manual" | "exclusions";

/** NamesEdit replaces one list in the current policy, preserving its other values and revision. */
export interface NamesEdit {
  list: DnsList;
  names: string[];
  resetEditor?: boolean;
}

/** DnsNames renders observed automatic names and two independently editable operator lists. */
@Component({
  selector: "hestia-dns-names",
  imports: [Tooltip, DatePipe, InputText, ButtonDirective],
  templateUrl: "./dns-names.component.html",
  styleUrl: "../../../styles/dns.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DnsNames {
  readonly snapshot = input.required<CheckedSnapshot>();
  readonly report = input<CheckedWarm | null>(null);
  readonly observationState = input.required<
    "loading" | "ready" | "unavailable"
  >();
  readonly disabled = input(false);
  readonly changeList = output<NamesEdit>();
  protected readonly editing = signal<string | null>(null);
  protected readonly draft = { manual: signal(""), exclusions: signal("") };
  private readonly notifications = inject(Notifications);
  protected readonly percent = new Intl.NumberFormat("ru-RU", {
    style: "percent",
    maximumFractionDigits: 2,
  });
  protected readonly lists = ["exclusions", "manual"] as const;

  /** edit copies the selected exclusion into its editor without removing the existing rule. */
  protected edit(name: string, input: HTMLInputElement): void {
    this.editing.set(name);
    this.draft.exclusions.set(name);
    input.focus();
  }

  /** clearEditor clears only the confirmed list's input or an explicitly cancelled edit. */
  clearEditor(list: DnsList): void {
    this.draft[list].set("");
    if (list === "exclusions") this.editing.set(null);
  }

  /** add prepares a bounded atomic add or rename, keeping the input until the server acknowledges it. */
  protected add(list: DnsList, raw: string, fromEditor: boolean): void {
    const name = canonicalDomain(raw),
      values = this.snapshot().policy[list];
    const original =
      list === "exclusions" && fromEditor ? this.editing() : null;
    if (!name) {
      this.notifications.show(
        "error",
        "Введите точное доменное имя без маски или IP-адреса.",
      );
      return;
    }
    if (original && !values.includes(original)) {
      this.notifications.show(
        "error",
        "Исходное исключение изменилось. Отмените редактирование и выберите запись заново.",
      );
      return;
    }
    if (values.includes(name) && name !== original) {
      this.notifications.show("error", "Такой домен уже есть в списке.");
      return;
    }
    if (!original && values.length >= 4096) {
      this.notifications.show("error", "Достигнут предел в 4096 доменов.");
      return;
    }
    this.changeList.emit({
      list,
      names: original
        ? values.map((v) => (v === original ? name : v))
        : [...values, name],
      resetEditor: fromEditor,
    });
  }

  /** remove requests removal only from the chosen list, leaving the other membership unchanged. */
  protected remove(list: DnsList, name: string): void {
    this.changeList.emit({
      list,
      names: this.snapshot().policy[list].filter((entry) => entry !== name),
      resetEditor: list === "exclusions" && this.editing() === name,
    });
  }
}
