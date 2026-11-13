import { Tooltip } from "primeng/tooltip";
import { Toast } from "primeng/toast";
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  effect,
  inject,
  input,
  signal,
  untracked,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { ButtonDirective } from "primeng/button";
import { InputText } from "primeng/inputtext";
import { firstValueFrom, timeout } from "rxjs";
import { takeUntilDestroyed } from "@angular/core/rxjs-interop";
import { PanelService } from "../../services/api/generated/api/panel.service";
import { Notifications } from "../../services/notifications.service";

import type { PhysicalInventory as Inventory } from "../../services/api/generated/model/physicalInventory";
import type { WifiConnection as WifiProfile } from "../../services/api/generated/model/wifiConnection";
type Band = WifiProfile["band"];
type Security = WifiProfile["security"];

/** validInventory validates public interface and Wi-Fi profile data before exposing any actions. */
function validInventory(value: unknown): value is Inventory {
  if (
    !value ||
    typeof value !== "object" ||
    !("wifiAvailable" in value) ||
    typeof value.wifiAvailable !== "boolean" ||
    !("interfaces" in value) ||
    !Array.isArray(value.interfaces) ||
    !("wifiProfiles" in value) ||
    !Array.isArray(value.wifiProfiles)
  )
    return false;
  return (
    value.interfaces.every(
      (a: unknown) =>
        a !== null &&
        typeof a === "object" &&
        "interfaceName" in a &&
        typeof a.interfaceName === "string" &&
        (!("providerName" in a) ||
          (typeof a.providerName === "string" &&
            a.providerName.trim().length > 0 &&
            a.providerName.length <= 80 &&
            !/\p{Cc}/u.test(a.providerName))) &&
        "kind" in a &&
        (a.kind === "ethernet" || a.kind === "wifi") &&
        "carrierState" in a &&
        (a.carrierState === "up" ||
          a.carrierState === "down" ||
          a.carrierState === "unknown") &&
        "online" in a &&
        typeof a.online === "boolean" &&
        a.online === (a.carrierState === "up") &&
        "present" in a &&
        typeof a.present === "boolean" &&
        "exitIds" in a &&
        Array.isArray(a.exitIds) &&
        a.exitIds.every((id: unknown) => typeof id === "string"),
    ) &&
    value.wifiProfiles.every(
      (p: unknown) =>
        p !== null &&
        typeof p === "object" &&
        "id" in p &&
        typeof p.id === "string" &&
        "interfaceName" in p &&
        typeof p.interfaceName === "string" &&
        "ssid" in p &&
        typeof p.ssid === "string" &&
        "band" in p &&
        (p.band === "2.4" || p.band === "5") &&
        "security" in p &&
        (p.security === "wpa-psk" || p.security === "open") &&
        "active" in p &&
        typeof p.active === "boolean",
    )
  );
}

/** PhysicalConnections manages Hestia wireless client profiles and radio inventory. */
@Component({
  selector: "hestia-physical-connections",
  imports: [Tooltip, Toast, FormsModule, ButtonDirective, InputText],
  templateUrl: "./physical-connections.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class PhysicalConnections {
  readonly revision = input(0);
  private readonly api = inject(PanelService);
  private readonly notifications = inject(Notifications);
  private readonly destroy = inject(DestroyRef);
  protected readonly inventory = signal<Inventory | null>(null);
  protected readonly failed = signal(false);
  protected readonly busy = signal(false);
  protected readonly reading = signal(false);
  protected readonly editing = signal<WifiProfile | null>(null);
  protected readonly radios = computed(
    () =>
      this.inventory()?.interfaces.filter(
        (a) => a.kind === "wifi" && a.present,
      ) ?? [],
  );
  protected adapter = "";
  protected ssid = "";
  protected band: Band = "2.4";
  protected security: Security = "wpa-psk";
  protected password = "";
  private generation = 0;

  /** Refreshes the inventory on entry, explicit refresh and while the visible page is open. */
  constructor() {
    effect(() => {
      this.revision();
      untracked(() => void this.load());
    });
    const timer = setInterval(() => {
      if (
        document.visibilityState === "visible" &&
        !this.busy() &&
        !this.reading()
      )
        void this.load();
    }, 3000);
    this.destroy.onDestroy(() => {
      clearInterval(timer);
      this.generation++;
      this.password = "";
    });
  }

  /** load discards out-of-order reads and preserves the last successful inventory during an outage. */
  private async load(): Promise<void> {
    if (this.reading()) return;
    const generation = ++this.generation;
    this.reading.set(true);
    try {
      const result: unknown = await firstValueFrom(
        this.api
          .listPhysicalConnections()
          .pipe(timeout(10000), takeUntilDestroyed(this.destroy)),
      );
      if (generation !== this.generation) return;
      if (!validInventory(result))
        throw new Error("Invalid physical inventory");
      this.inventory.set(result);
      this.failed.set(false);
    } catch {
      if (generation === this.generation && !this.failed()) {
        this.failed.set(true);
        this.notifications.show(
          "error",
          "Не удалось обновить список физических подключений.",
        );
      }
    } finally {
      if (generation === this.generation) this.reading.set(false);
    }
  }

  /** openWifi populates public settings and always starts with a blank password input. */
  protected openWifi(
    dialog: HTMLDialogElement,
    profile: WifiProfile | null,
  ): void {
    this.editing.set(profile);
    this.adapter =
      profile?.interfaceName ?? this.radios()[0]?.interfaceName ?? "";
    this.ssid = profile?.ssid ?? "";
    this.security = profile?.security ?? "wpa-psk";
    this.band = profile?.band ?? "2.4";
    this.password = "";
    dialog.showModal();
  }

  /** closeWifi clears draft credentials when a dialog is dismissed. */
  protected closeWifi(): void {
    this.password = "";
    this.editing.set(null);
  }

  /** saveWifi applies the selected band and SSID only to the specified radio, retaining the draft on failure. */
  protected async saveWifi(dialog: HTMLDialogElement): Promise<void> {
    if (this.busy()) return;
    const profile = this.editing(),
      bytes = new TextEncoder().encode(this.ssid).length;
    if (
      !this.inventory()?.wifiAvailable ||
      !this.radios().some((radio) => radio.interfaceName === this.adapter) ||
      !bytes ||
      bytes > 32 ||
      /\p{Cc}/u.test(this.ssid)
    ) {
      this.notifications.show(
        "error",
        "Выберите адаптер и введите SSID длиной до 32 байт.",
      );
      return;
    }
    const needsPassword =
      this.security === "wpa-psk" &&
      (!profile || profile.security !== "wpa-psk" || this.password.length > 0);
    const passwordBytes = new TextEncoder().encode(this.password).length;
    if (
      needsPassword &&
      !(
        (passwordBytes >= 8 &&
          passwordBytes <= 63 &&
          !/\p{Cc}/u.test(this.password)) ||
        /^[a-f\d]{64}$/i.test(this.password)
      )
    ) {
      this.notifications.show(
        "error",
        "Введите пароль длиной 8–63 байта или ключ из 64 шестнадцатеричных цифр.",
      );
      return;
    }
    const settings = {
      interfaceName: this.adapter,
      ssid: this.ssid,
      band: this.band,
      security: this.security,
      ...(needsPassword ? { password: this.password } : {}),
    };
    this.busy.set(true);
    try {
      await firstValueFrom(
        profile
          ? this.api.saveWifiConnection(profile.id, settings)
          : this.api.createWifiConnection(settings),
      );
      dialog.close();
      this.password = "";
      await this.load();
      this.notifications.show("success", "Wi-Fi подключение сохранено.");
    } catch {
      this.notifications.show(
        "error",
        "Не удалось подключиться. Проверьте адаптер, диапазон, SSID и пароль сети.",
      );
    } finally {
      this.busy.set(false);
    }
  }

  /** removeWifi deletes only the explicitly confirmed Hestia wireless profile. */
  protected async removeWifi(profile: WifiProfile): Promise<void> {
    if (
      this.busy() ||
      !window.confirm("Удалить подключение Wi-Fi «" + profile.ssid + "»?")
    )
      return;
    this.busy.set(true);
    try {
      await firstValueFrom(this.api.deleteWifiConnection(profile.id));
      await this.load();
      this.notifications.show("success", "Подключение Wi-Fi удалено.");
    } catch {
      this.notifications.show("error", "Не удалось удалить подключение Wi-Fi.");
    } finally {
      this.busy.set(false);
    }
  }
}
