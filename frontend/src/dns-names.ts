import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
  signal,
} from "@angular/core";

/** An observed DNS context includes the client count and time of the most recent successful refresh. */
interface WarmName {
  readonly name: string;
  readonly recordType: "A" | "AAAA";
  readonly exit: string;
  readonly resolver: string;
  readonly requests: number;
  readonly refreshedAt: string | null;
}

/** null means the warm-name source has not been integrated; an empty list means a successful read with no names. */
@Component({
  selector: "hestia-dns-names",
  templateUrl: "./dns-names.html",
  styleUrl: "./dns.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class DnsNames {
  readonly observations = input<readonly WarmName[] | null>(null);
  protected readonly query = signal("");
  protected readonly visible = computed(() => {
    const rows = this.observations(),
      query = this.query().trim().toLowerCase();
    return rows?.filter((row) => row.name.toLowerCase().includes(query)) ?? [];
  });
}
