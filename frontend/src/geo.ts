import { Notifications } from "./notifications";
import { groupName } from "./snapshot";
import {
  ChangeDetectionStrategy,
  Component,
  Injectable,
  computed,
  inject,
  signal,
} from "@angular/core";
import { FormControl, ReactiveFormsModule } from "@angular/forms";
import { SnapshotState } from "./snapshot-state";

import { type MapDraft, type CountryBlock, previewCountry } from "./geo-policy";
const emptyMap: MapDraft = { countries: [], blocks: [], world: "" };
// ISO 3166-1 alpha-2 codes, public-domain IANA tzdata iso3166.tab.
const regionCodes =
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(
    " ",
  );
const names = new Intl.DisplayNames("ru", { type: "region" });

/** MapDraftState retains the unsent policy across routes for this browser session. */
@Injectable({ providedIn: "root" })
class MapDraftState {
  readonly map = signal<MapDraft>(emptyMap);
}

/** GeoScreen prepares country assignments and previews precedence against the current group inventory. */
@Component({
  selector: "hestia-geo",
  imports: [ReactiveFormsModule],
  templateUrl: "./geo.html",
  styleUrl: "./geo.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class GeoScreen {
  private readonly notifications = inject(Notifications);
  protected readonly groupName = groupName;
  protected readonly inventory = inject(SnapshotState);
  protected readonly map = inject(MapDraftState).map;
  protected readonly groups = computed(() => {
    const view = this.inventory.view();
    return view.kind === "ready" ? view.snapshot.groups : [];
  });
  protected readonly countries = regionCodes
    .map((code) => ({ code, label: names.of(code) ?? code }))
    .sort((a, b) => a.label.localeCompare(b.label, "ru"));
  protected readonly country = new FormControl("", { nonNullable: true });
  protected readonly countryGroup = new FormControl("", { nonNullable: true });
  protected readonly blockName = new FormControl("", { nonNullable: true });
  protected readonly blockCountries = new FormControl("", {
    nonNullable: true,
  });
  protected readonly blockGroup = new FormControl("", { nonNullable: true });
  protected readonly editingBlock = signal<string | null>(null);
  protected readonly countryError = signal("");
  protected readonly blockError = signal("");
  protected readonly previewCountry = signal("");
  protected readonly preview = computed(() => {
    const code = this.previewCountry();
    const map = this.map();
    const groups = this.groups();
    if (!groups.length) return "Для проверки нужен снимок групп.";
    const result = previewCountry(code, map, groups);
    const labels = {
      unknown: "Страна не определена",
      country: "Правило страны",
      world: "Остальной мир",
      default: "Группа по умолчанию",
    };
    const reason =
      result.reason === "block"
        ? "Блок «" + result.block + "»"
        : labels[result.reason];
    return (
      reason +
      " → " +
      (groups.some((group) => group.id === result.group)
        ? result.group
        : "Группа отсутствует в снимке")
    );
  });

  /** countryLabel returns the localized name and stored ISO code used by country rules. */
  protected countryLabel(code: string): string {
    return (names.of(code) ?? code) + " (" + code + ")";
  }

  /** selectCountry loads any existing mapping into the local country editor. */
  protected selectCountry(code: string): void {
    this.countryGroup.setValue(
      this.map().countries.find((rule) => rule.country === code)?.group ?? "",
    );
    this.countryError.set("");
  }

  /** saveCountry inserts or replaces one local assignment for a valid current group. */
  protected saveCountry(): void {
    const country = this.country.value,
      group = this.countryGroup.value;
    if (
      !regionCodes.includes(country) ||
      !this.groups().some((entry) => entry.id === group)
    ) {
      this.countryError.set("Выберите страну и группу из снимка.");
      return;
    }
    this.map.update((map) => ({
      ...map,
      countries: [
        ...map.countries.filter((rule) => rule.country !== country),
        { country, group },
      ],
    }));
    this.countryError.set("");
    this.notifications.show(
      "success",
      `Назначение для страны ${this.countryLabel(country)} добавлено в черновик.`,
    );
  }

  /** removeCountry removes just the explicit assignment and leaves block fallbacks intact. */
  protected removeCountry(code: string): void {
    this.map.update((map) => ({
      ...map,
      countries: map.countries.filter((rule) => rule.country !== code),
    }));
    if (this.country.value === code) this.selectCountry(code);
  }

  /** editBlock copies the selected local block to the editor without changing its priority. */
  protected editBlock(block: CountryBlock): void {
    this.editingBlock.set(block.name);
    this.blockName.setValue(block.name);
    this.blockCountries.setValue(block.countries.join(", "));
    this.blockGroup.setValue(block.group);
    this.blockError.set("");
  }

  /** clearBlock discards only the current block form. */
  protected clearBlock(): void {
    this.editingBlock.set(null);
    this.blockName.reset();
    this.blockCountries.reset();
    this.blockGroup.reset();
    this.blockError.set("");
  }

  /** saveBlock validates membership and saves a block in place or appends a new lowest-priority block. */
  protected saveBlock(): void {
    const name = this.blockName.value.trim(),
      group = this.blockGroup.value;
    const countries = [
      ...new Set(
        this.blockCountries.value
          .trim()
          .toUpperCase()
          .split(/[\s,;]+/)
          .filter(Boolean),
      ),
    ];
    const editing = this.editingBlock();
    if (
      !name ||
      !countries.length ||
      countries.some((code) => !regionCodes.includes(code)) ||
      !this.groups().some((entry) => entry.id === group)
    ) {
      this.blockError.set(
        "Введите название, коды стран ISO и выберите группу.",
      );
      return;
    }
    if (
      this.map().blocks.some(
        (block) => block.name === name && block.name !== editing,
      )
    ) {
      this.blockError.set("Блок с таким названием уже есть в черновике.");
      return;
    }
    const block = { name, group, countries };
    this.map.update((map) => ({
      ...map,
      blocks:
        editing === null
          ? [...map.blocks, block]
          : map.blocks.map((old) => (old.name === editing ? block : old)),
    }));
    this.clearBlock();
    this.notifications.show("success", `Блок «${name}» сохранён в черновике.`);
  }

  /** moveBlock changes priority by one position within the local ordered block list. */
  protected moveBlock(index: number, offset: -1 | 1): void {
    this.map.update((map) => {
      const blocks = [...map.blocks],
        dest = index + offset;
      if (dest < 0 || dest >= blocks.length) return map;
      [blocks[index], blocks[dest]] = [blocks[dest], blocks[index]];
      return { ...map, blocks };
    });
  }

  /** removeBlock removes a draft block and clears its active form if needed. */
  protected removeBlock(name: string): void {
    this.map.update((map) => ({
      ...map,
      blocks: map.blocks.filter((block) => block.name !== name),
    }));
    if (this.editingBlock() === name) this.clearBlock();
  }

  /** setWorld chooses the fallback for known countries without an applicable country or block rule. */
  protected setWorld(group: string): void {
    if (group === "" || this.groups().some((entry) => entry.id === group))
      this.map.update((map) => ({ ...map, world: group }));
  }

  /** reset discards all local assignments and resets form state without issuing a request. */
  protected reset(): void {
    this.map.set(emptyMap);
    this.country.reset();
    this.countryGroup.reset();
    this.countryError.set("");
    this.clearBlock();
    this.previewCountry.set("");
  }
}
