import { parseDocument } from "yaml";

/** ClientFields contains the settings taken from an official client profile before any save. */
interface ClientFields {
  server: string;
  port: number;
  password: string;
  serverName: string;
  ca: string;
  ignoresSocks: boolean;
}

/** fields rejects non-mappings and options that the gateway cannot reproduce. */
function fields(
  value: unknown,
  path: string,
  supported: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Ожидался раздел ${path || "профиля"}.`);
  }
  for (const key of Object.keys(value)) {
    if (!supported.includes(key))
      throw new Error(`Параметр ${path}${key} пока не поддерживается.`);
  }
  return value as Record<string, unknown>;
}

/** textOption validates each scalar before returning its exact text, including password punctuation. */
function textOption(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim() || /\p{Cc}/u.test(value))
    throw new Error(`Проверьте значение ${name}.`);
  return value;
}

/** parseClientProfile reads a bounded single-document profile without expanding aliases or applying gateway settings. */
export function parseClientProfile(source: string): ClientFields {
  if (source.length > 65536) throw new Error("Размер YAML превышает 64 КиБ.");
  let data: unknown;
  try {
    const doc = parseDocument(source, {
      schema: "failsafe",
      prettyErrors: false,
      stringKeys: true,
    });
    if (doc.errors.length || doc.warnings.length) throw new Error();
    data = doc.toJS({ maxAliasCount: 0 });
  } catch {
    throw new Error(
      "Некорректный YAML. Проверьте структуру и повторяющиеся поля.",
    );
  }
  const profile = fields(data, "", ["server", "auth", "tls", "socks5"]);
  const address = textOption(profile["server"], "server");
  const match =
    /^(?:\[([\da-fA-F:.]+)\]|([a-zA-Z0-9.-]+))(?::([0-9]{1,5}))?$/u.exec(
      address,
    );
  const port = Number(match?.[3] ?? 443);
  if (!match || port < 1 || port > 65535)
    throw new Error("В server укажите адрес и один UDP-порт от 1 до 65535.");
  const tls =
    profile["tls"] === undefined
      ? {}
      : fields(profile["tls"], "tls.", ["sni", "ca", "insecure"]);
  if ("insecure" in tls && tls["insecure"] !== "false")
    throw new Error(
      "Параметр tls.insecure отключает обязательную проверку сертификата.",
    );
  return {
    server: match[1] ?? match[2],
    port,
    password: textOption(profile["auth"], "auth"),
    serverName: "sni" in tls ? textOption(tls["sni"], "tls.sni") : "",
    ca: "ca" in tls ? textOption(tls["ca"], "tls.ca") : "",
    ignoresSocks: "socks5" in profile,
  };
}

/** isPublicCertificateBundle checks bounded PEM envelopes line by line; the gateway validates each X.509 certificate. */
export function isPublicCertificateBundle(text: string): boolean {
  if (!text || text.length > 24576) return false;
  let inside = false;
  let content = false;
  let completed = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (!inside) {
      if (line !== "-----BEGIN CERTIFICATE-----") return false;
      inside = true;
      content = false;
    } else if (line === "-----END CERTIFICATE-----") {
      if (!content) return false;
      completed = true;
      inside = false;
    } else if (/^[A-Za-z0-9+/]+={0,2}$/u.test(line)) {
      content = true;
    } else return false;
  }
  return completed && !inside;
}
