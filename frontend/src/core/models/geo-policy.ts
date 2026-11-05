import type { CountryMap } from "../services/api/generated/model/countryMap";

// ISO 3166-1 alpha-2 codes, public-domain IANA tzdata iso3166.tab.
export const regionCodes =
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(
    " ",
  );

/** isCountryMap accepts only versioned gateway maps with one nonempty group ID per ISO country. */
export function isCountryMap(value: unknown): value is CountryMap {
  if (
    typeof value !== "object" ||
    value === null ||
    Object.keys(value).length !== 3 ||
    !("enabled" in value) ||
    typeof value.enabled !== "boolean" ||
    !("version" in value) ||
    typeof value.version !== "string" ||
    !value.version.trim() ||
    value.version.length > 64 ||
    !("assignments" in value) ||
    typeof value.assignments !== "object" ||
    value.assignments === null ||
    Array.isArray(value.assignments)
  )
    return false;
  const entries: [string, unknown][] = Object.entries(value.assignments);
  return (
    entries.length === regionCodes.length &&
    entries.every(
      ([code, id]) =>
        regionCodes.includes(code) &&
        typeof id === "string" &&
        id.trim().length > 0,
    )
  );
}
