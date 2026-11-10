import {
  ChangeDetectionStrategy,
  Component,
  inject,
  input,
  output,
} from "@angular/core";
import { DialogModule } from "primeng/dialog";
import type { TrafficEvent } from "../../services/api/generated/model/trafficEvent";
import { ConnectionCatalog } from "../../services/connection-catalog.service";

/** TrafficEvents displays the selected persisted event, including only evidence available from the gateway. */
@Component({
  selector: "hestia-traffic-details",
  imports: [DialogModule],
  templateUrl: "./traffic-events.component.html",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TrafficEvents {
  readonly event = input.required<TrafficEvent>();
  readonly closed = output<void>();
  protected readonly catalog = inject(ConnectionCatalog);

  /** formatConntrackMark renders a numeric conntrack mark without implying a packet mark verdict. */
  protected formatConntrackMark(mark: number | undefined): string {
    return mark === undefined
      ? "Нет данных"
      : `0x${mark.toString(16).padStart(8, "0")}`;
  }
}
