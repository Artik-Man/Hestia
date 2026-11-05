/** WireGuardFormError carries a field- or line-specific message without copying any profile values. */
export class WireGuardFormError extends Error {}

/** Supported sections and fields mirror the gateway's single-peer .conf grammar. */
const requiredInterfaceFields = ["Address", "DNS", "PrivateKey"] as const;
export const localFields = [
  ...requiredInterfaceFields,
  "HeaderProtectionKey",
] as const;
const extraInterfaceFields = [
  "MTU",
  "FwMark",
  "Jc",
  "Jmin",
  "Jmax",
  "S1",
  "S2",
  "S3",
  "S4",
  "H1",
  "H2",
  "H3",
  "H4",
  "I1",
  "I2",
  "I3",
  "I4",
  "I5",
  "ContentPaddingAddition",
  "RekeyAfterTime",
  "RekeyTimeout",
  "RejectAfterTime",
  "KeepaliveTimeout",
  "MaxHandshakeAttempts",
  "RandomTrailers",
  "DisableCookies",
] as const;
export const remoteFields = [
  "Endpoint",
  "AllowedIPs",
  "PublicKey",
  "PresharedKey",
] as const;
const interfaceFields = [...localFields, ...extraInterfaceFields] as const;
const peerFields = [...remoteFields, "PersistentKeepalive"] as const;
const sections = { Interface: interfaceFields, Peer: peerFields } as const;
export type WireGuardField =
  (typeof interfaceFields)[number] | (typeof peerFields)[number];
export type WireGuardValues = Partial<Record<WireGuardField, string>>;
const requiredFields = [
  ...requiredInterfaceFields,
  "PublicKey",
  "Endpoint",
  "AllowedIPs",
] as const;
export const optionalFields = [
  ...extraInterfaceFields,
  "PersistentKeepalive",
] as const;
export const placeholders: Partial<Record<WireGuardField, string>> = {
  Address: "10.0.0.2/32",
  DNS: "10.0.0.1",
  Endpoint: "vpn.example.org:51820",
  AllowedIPs: "0.0.0.0/0",
};
export const maxProfileBytes = 32 * 1024;

const labels: Partial<Record<WireGuardField, string>> = {
  Address: "Адрес интерфейса (Address)",
  DNS: "DNS",
  PrivateKey: "Приватный ключ (PrivateKey)",
  HeaderProtectionKey:
    "Ключ защиты заголовка (HeaderProtectionKey, необязательно)",
  PublicKey: "Публичный ключ пира (PublicKey)",
  Endpoint: "Адрес и порт пира (Endpoint)",
  AllowedIPs: "Разрешённые сети (AllowedIPs)",
  PresharedKey: "Общий ключ (PresharedKey, необязательно)",
};

/** fieldLabel gives each editor input an accessible name including its .conf directive. */
export function fieldLabel(field: WireGuardField): string {
  return labels[field] ?? field;
}

/** parseWireGuardConfig maps one Interface and Peer into independently editable fields, rejecting unsupported or duplicate input atomically. */
export function parseWireGuardConfig(text: string): WireGuardValues {
  if (
    !text.trim() ||
    new TextEncoder().encode(text).length > maxProfileBytes ||
    text.includes("\0")
  ) {
    throw new WireGuardFormError(
      "Некорректный файл конфигурации. Максимальный размер — 32 КиБ.",
    );
  }
  let section: keyof typeof sections | undefined;
  const seen = new Set<keyof typeof sections>();
  const values: WireGuardValues = {};
  for (const [index, raw] of text.split("\n").entries()) {
    const line = raw.trim();
    if (!line || /^[#;]/u.test(line)) continue;
    if (line === "[Interface]" || line === "[Peer]") {
      section = line === "[Interface]" ? "Interface" : "Peer";
      if (seen.has(section))
        throw new WireGuardFormError(
          "Допускается только одна секция [Interface] и одна [Peer].",
        );
      seen.add(section);
      continue;
    }
    const eq = line.indexOf("=");
    const key = eq > 0 ? line.slice(0, eq).trim() : "";
    const value = eq > 0 ? line.slice(eq + 1).trim() : "";
    const field = section && sections[section].find((item) => item === key);
    if (
      !field ||
      !value ||
      /[\r\n]/u.test(value) ||
      Object.hasOwn(values, field)
    ) {
      throw new WireGuardFormError(
        `Строка ${index + 1}: неизвестный или повторяющийся параметр, пустое значение либо неверная секция.`,
      );
    }
    values[field] = value;
  }
  if (seen.size !== 2)
    throw new WireGuardFormError(
      "В файле должны быть секции [Interface] и [Peer].",
    );
  requireFields(values);
  return values;
}

/** requireFields rejects incomplete profiles using safe field names for import and manual entry. */
function requireFields(values: WireGuardValues): void {
  for (const field of requiredFields) {
    if (!values[field]?.trim())
      throw new WireGuardFormError(`Заполните поле «${fieldLabel(field)}».`);
  }
}

/** buildWireGuardConfig emits only supported directives, validates required fields and prevents injected directives in values. */
export function buildWireGuardConfig(values: WireGuardValues): string {
  requireFields(values);
  const lines: string[] = [];
  for (const [section, keys] of Object.entries(sections)) {
    lines.push(`[${section}]`);
    for (const key of keys) {
      const raw = values[key] ?? "";
      if (/[\r\n\0]/u.test(raw))
        throw new WireGuardFormError(
          `Поле «${fieldLabel(key)}» должно занимать одну строку.`,
        );
      const value = raw.trim();
      if (value) lines.push(`${key} = ${value}`);
    }
    lines.push("");
  }
  const config = lines.join("\n");
  if (new TextEncoder().encode(config).length > maxProfileBytes)
    throw new WireGuardFormError("Размер конфигурации превышает 32 КиБ.");
  return config;
}
