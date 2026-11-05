/** normalizeHysteriaHost returns a bare IP or ASCII hostname for dialing and TLS, or null on invalid input. */
export function normalizeHysteriaHost(value: string): string | null {
  if (value.includes(":")) {
    const literal =
      value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
    if (!/^[a-fA-F0-9:.]+$/.test(literal)) return null;
    try {
      new URL("http://[" + literal + "]/");
      return literal;
    } catch {
      return null;
    }
  }
  if (/^[0-9.]+$/.test(value)) {
    const parts = value.split(".");
    return parts.length === 4 &&
      parts.every(
        (part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255,
      )
      ? value
      : null;
  }
  const labels = value.replace(/\.$/u, "").split(".");
  return value.length <= 253 &&
    labels.every((label) =>
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label),
    )
    ? value
    : null;
}
