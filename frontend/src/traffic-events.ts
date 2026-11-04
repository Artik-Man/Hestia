import {
  ChangeDetectionStrategy,
  Component,
  computed,
  input,
} from "@angular/core";
import { RouterLink } from "@angular/router";

import {
  filterFlows,
  type FlowEvent,
  type FlowProtocol,
} from "./traffic-observations";

/** TrafficEvents filters a known event window and exposes expandable flow and DNS details. */
@Component({
  selector: "hestia-traffic-events",
  imports: [RouterLink],
  templateUrl: "./traffic-events.html",
  styleUrl: "./traffic-quality.css",
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class TrafficEvents {
  readonly events = input.required<readonly FlowEvent[] | null>();
  readonly query = input.required<string>();
  readonly protocol = input.required<FlowProtocol | "">();
  readonly periodHours = input.required<number>();

  protected readonly matches = computed(() => {
    const events = this.events();
    if (events === null) return null;
    return filterFlows(
      events,
      this.query(),
      this.protocol(),
      this.periodHours(),
      Date.now(),
    );
  });
}
