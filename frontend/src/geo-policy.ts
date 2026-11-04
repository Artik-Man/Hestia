import type { Group } from "./api/generated/model/group";

export interface CountryRule {
  readonly country: string;
  readonly group: string;
}
export interface CountryBlock {
  readonly name: string;
  readonly countries: readonly string[];
  readonly group: string;
}
export interface MapDraft {
  readonly countries: readonly CountryRule[];
  readonly blocks: readonly CountryBlock[];
  readonly world: string;
}

type Preview =
  | {
      reason: "country" | "world" | "default" | "unknown";
      group: string | undefined;
    }
  | { reason: "block"; block: string; group: string };

/** previewCountry resolves the unsent draft using country, ordered block, known-world and default precedence. */
export function previewCountry(
  code: string,
  map: MapDraft,
  groups: readonly Group[],
): Preview {
  const fallback = groups.find((group) => group.isDefault)?.id;
  if (!code) return { reason: "unknown", group: fallback };
  const country = map.countries.find((entry) => entry.country === code);
  if (country) return { reason: "country", group: country.group };
  const block = map.blocks.find((entry) => entry.countries.includes(code));
  if (block) return { reason: "block", block: block.name, group: block.group };
  if (map.world) return { reason: "world", group: map.world };
  return { reason: "default", group: fallback };
}
