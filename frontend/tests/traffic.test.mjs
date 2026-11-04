import { test } from "node:test";
import assert from "node:assert/strict";
import { filterFlows } from "../src/traffic-observations.ts";

test("IPv6 without a domain survives combined search, protocol and time filters", () => {
  const at = Date.parse("2026-11-04T09:00:00Z");
  const event = {
    id: "match",
    address: "2001:db8::9",
    fakeIP: null,
    domain: null,
    protocol: "UDP",
    time: "2026-11-04T08:00:00Z",
  };
  const events = [
    event,
    { ...event, id: "tcp", protocol: "TCP" },
    { ...event, id: "old", time: "2026-11-04T07:59:59Z" },
    { ...event, id: "future", time: "2026-11-04T09:00:01Z" },
    { ...event, id: "v4", address: "198.51.100.9" },
  ];
  assert.deepEqual(
    filterFlows(events, " DB8:: ", "UDP", 1, at).map((row) => row.id),
    ["match"],
  );
});
