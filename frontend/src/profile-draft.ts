import {
  ChangeDetectionStrategy,
  Component,
  input,
  output,
  signal,
  OnChanges,
  inject,
} from "@angular/core";
import {
  FormBuilder,
  FormControl,
  FormRecord,
  ReactiveFormsModule,
  Validators,
} from "@angular/forms";
import type { Group } from "./api/generated/model/group";

import { validExitId, validHost, validSubnet } from "./profile-validation";

const protocols = ["SSTP", "VLESS", "WireGuard", "AmneziaWG"] as const;
type Protocol = (typeof protocols)[number];
/** Each proposed input belongs to one protocol and is stored only in this form. */
interface Field {
  key: string;
  label: string;
  secret?: boolean;
  optional?: boolean;
  pattern?: RegExp;
  options?: readonly string[];
}
const keyPattern = /^[A-Za-z0-9+/]{43}=$/;
const wireguard: readonly Field[] = [
  { key: "address", label: "Адрес интерфейса с префиксом" },
  {
    key: "privateKey",
    label: "Приватный ключ клиента (Base64)",
    secret: true,
    pattern: keyPattern,
  },
  {
    key: "peerKey",
    label: "Публичный ключ сервера (Base64)",
    pattern: keyPattern,
  },
  { key: "allowedIps", label: "Разрешённые сети (CIDR через запятую)" },
];
const fields: Record<Protocol, readonly Field[]> = {
  SSTP: [
    { key: "username", label: "Имя пользователя" },
    { key: "password", label: "Пароль SSTP", secret: true },
  ],
  VLESS: [
    {
      key: "uuid",
      label: "UUID клиента",
      secret: true,
      pattern: /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i,
    },
    {
      key: "transport",
      label: "Транспорт",
      options: ["TCP", "WebSocket", "gRPC"],
    },
    {
      key: "security",
      label: "Защита транспорта",
      options: ["TLS", "REALITY"],
    },
    { key: "serverName", label: "Имя сервера TLS" },
    { key: "flow", label: "Flow (при необходимости)", optional: true },
  ],
  WireGuard: wireguard,
  AmneziaWG: [
    ...wireguard,
    {
      key: "obfuscation",
      label: "Параметры обфускации (по одному имя=значение в строке)",
      pattern: /^\w+\s*=\s*\S[^\n]*(?:\n\w+\s*=\s*\S[^\n]*)*$/,
    },
  ],
};

/** ProfileDraft validates proposed client settings locally; closing it destroys the controls, including keys. */
@Component({
  selector: "hestia-profile-draft",
  imports: [ReactiveFormsModule],
  templateUrl: "./profile-draft.html",
  styleUrl: "./editor.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class ProfileDraft implements OnChanges {
  readonly groups = input.required<readonly Group[]>();
  readonly exit = input<string | null>(null);
  readonly closed = output<void>();
  protected readonly protocols = protocols;
  protected readonly protocol = signal<Protocol | null>(null);
  protected readonly activeFields = signal<readonly Field[]>([]);
  protected readonly extra = new FormRecord<FormControl<string>>({});
  private readonly builder = inject(FormBuilder).nonNullable;
  protected readonly form = this.builder.group({
    id: ["", Validators.required],
    group: ["", Validators.required],
    priority: [1, [Validators.required, Validators.min(1)]],
    host: ["", Validators.required],
    port: [
      443,
      [Validators.required, Validators.min(1), Validators.max(65535)],
    ],
    dns: [""],
    desired: [""],
    extra: this.extra,
  });
  protected readonly report = signal("");
  /** ngOnChanges clears protocol-specific data and initializes only identity, group and position known from the snapshot. */
  ngOnChanges(): void {
    const id = this.exit();
    const group = this.groups().find((group) =>
      group.exits.some((exit) => exit.id === id),
    );
    this.selectProtocol("");
    this.form.reset({
      id: id ?? "",
      group: group?.id ?? "",
      priority: group ? group.exits.findIndex((exit) => exit.id === id) + 1 : 1,
      host: "",
      port: 443,
      dns: "",
      desired: "",
    });
  }
  /** selectProtocol replaces all private controls when the protocol changes so hidden credentials cannot be retained. */
  protected selectProtocol(value: string): void {
    const protocol = protocols.find((p) => p === value) ?? null;
    this.protocol.set(protocol);
    this.activeFields.set(protocol ? fields[protocol] : []);
    for (const key of Object.keys(this.extra.controls))
      this.extra.removeControl(key);
    for (const field of this.activeFields()) {
      const validators = field.optional
        ? []
        : [Validators.required, Validators.pattern(/\S/)];
      if (field.pattern) validators.push(Validators.pattern(field.pattern));
      this.extra.addControl(
        field.key,
        this.builder.control(field.options?.[0] ?? "", validators),
      );
    }
    this.form.controls.port.setValue(
      protocol === "WireGuard" || protocol === "AmneziaWG" ? 51820 : 443,
    );
    this.report.set("");
  }
  /** check verifies local syntax and ordering, identifies bad inputs and never initiates a connection or persists the profile. */
  protected check(): void {
    const value = this.form.getRawValue();
    const group = this.groups().find((group) => group.id === value.group);
    const protocol = this.protocol();
    this.form.markAllAsTouched();
    if (!protocol) {
      this.report.set("Выберите тип подключения.");
      return;
    }
    if (!group) {
      this.report.set("Выберите существующую группу.");
      return;
    }
    if (
      !validExitId(value.id) ||
      (value.id !== this.exit() &&
        this.groups().some(
          (g) =>
            g.id === value.id || g.exits.some((exit) => exit.id === value.id),
        ))
    ) {
      this.report.set(
        "Укажите свободный идентификатор выхода без пробелов по краям и символов /, ?, # или обратной косой черты.",
      );
      return;
    }
    const capacity =
      group.exits.length +
      (group.exits.some((exit) => exit.id === this.exit()) ? 0 : 1);
    if (
      !Number.isInteger(value.priority) ||
      value.priority < 1 ||
      value.priority > capacity
    ) {
      this.report.set(
        "Приоритет должен быть целым числом от 1 до " + capacity + ".",
      );
      return;
    }
    if (
      !validHost(value.host) ||
      !Number.isInteger(value.port) ||
      this.form.controls.port.invalid
    ) {
      this.report.set("Проверьте адрес сервера и порт (1–65535).");
      return;
    }
    if (
      value.dns &&
      !value.dns.split(",").every((dns) => {
        const ip = dns.trim();
        return (/^[0-9.]+$/.test(ip) || ip.includes(":")) && validHost(ip);
      })
    ) {
      this.report.set("Укажите IP-адреса DNS через запятую.");
      return;
    }
    const invalidField = this.activeFields().find(
      (field) => this.extra.controls[field.key].invalid,
    );
    if (invalidField) {
      this.report.set("Проверьте поле «" + invalidField.label + "».");
      return;
    }
    if (
      (protocol === "WireGuard" || protocol === "AmneziaWG") &&
      (!validSubnet(value.extra.address) ||
        !value.extra.allowedIps.split(",").every(validSubnet))
    ) {
      this.report.set(
        "Проверьте адрес интерфейса и разрешённые сети в формате CIDR.",
      );
      return;
    }
    this.report.set(
      "Поля черновика прошли локальную проверку. Проверка туннеля и применение профиля требуют поддержки шлюза.",
    );
  }
}
