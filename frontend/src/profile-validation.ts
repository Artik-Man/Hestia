/** validExitId accepts an unreserved snapshot ID with no path delimiters or surrounding spaces. */
export function validExitId(id: string): boolean {
  return (
    id.length > 0 &&
    id.trim() === id &&
    ![".", "..", "deny"].includes(id) &&
    !/[/?#\\]/u.test(id)
  );
}

/** validHost accepts DNS hostnames, IPv4 and bracketed or unbracketed IPv6 without an embedded port. */
export function validHost(text: string): boolean {
  if (!text || /[\s/@?#\\]/u.test(text)) return false;
  if (text.includes(":")) {
    const literal =
      text.startsWith("[") && text.endsWith("]") ? text.slice(1, -1) : text;
    if (literal.includes("[") || literal.includes("]")) return false;
    try {
      return new URL("http://[" + literal + "]/").hostname.startsWith("[");
    } catch {
      return false;
    }
  }
  if (/^[0-9.]+$/.test(text))
    return (
      text.split(".").length === 4 &&
      text
        .split(".")
        .every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
    );
  return (
    text.length <= 253 &&
    text
      .split(".")
      .every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part))
  );
}

/** validSubnet checks an IP literal and its prefix length against the address family. */
export function validSubnet(text: string): boolean {
  const parts = text.trim().split("/");
  if (parts.length !== 2 || !/^\d{1,3}$/.test(parts[1])) return false;
  const ipv6 = parts[0].includes(":");
  return (
    (ipv6 || /^[0-9.]+$/.test(parts[0])) &&
    validHost(parts[0]) &&
    Number(parts[1]) <= (ipv6 ? 128 : 32)
  );
}
