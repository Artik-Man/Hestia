// ISO 3166-1 alpha-2 codes, public-domain IANA tzdata iso3166.tab.
export const regionCodes =
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(
    " ",
  );

/** CountryMap is a complete local draft keyed by ISO country code and stable group ID. */
export interface CountryMap {
  readonly enabled: boolean;
  readonly assignments: Readonly<Record<string, string>>;
}

/** initializeCountryMap captures the initial default for every country with routing disabled. */
export function initializeCountryMap(defaultGroup: string): CountryMap {
  return {
    enabled: false,
    assignments: Object.fromEntries(
      regionCodes.map((code) => [code, defaultGroup]),
    ),
  };
}

/** readCountryMap validates stored data without translating group IDs against a changing inventory. */
export function readCountryMap(raw: string | null): CountryMap | null {
  if (!raw) return null;
  try {
    const data: unknown = JSON.parse(raw);
    if (
      typeof data !== "object" ||
      data === null ||
      !("enabled" in data) ||
      typeof data.enabled !== "boolean" ||
      !("assignments" in data)
    )
      return null;
    const values = data.assignments;
    if (typeof values !== "object" || values === null || Array.isArray(values))
      return null;
    const entries: [string, unknown][] = Object.entries(values);
    if (entries.length !== regionCodes.length) return null;
    const assignments: Record<string, string> = {};
    for (const [code, id] of entries) {
      if (!regionCodes.includes(code) || typeof id !== "string" || !id.trim())
        return null;
      assignments[code] = id;
    }
    return { enabled: data.enabled, assignments };
  } catch {
    return null;
  }
}
