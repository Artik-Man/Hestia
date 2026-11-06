#!/usr/bin/python3
"""Opt-in warming of recently frequent IN/A names for a controlled dual-uplink DNS lab."""

import argparse
import asyncio
import contextvars
import importlib
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic

import dns.message

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
rotation = importlib.import_module("dns-rotation.cache")
MIN_GAP = 0.25
MAX_NAMES = 128
MAX_VISITS = 256
MAX_WARM_JOBS = 4
MAX_FETCHES = 32


@dataclass(frozen=True)
class Config:
    """Threshold and monotonic-time intervals used by the experimental scheduler."""

    min_visits: int
    window_seconds: float
    refresh_seconds: float

    def __post_init__(self):
        """Reject nonfinite or impractical periods and thresholds beyond the per-name deduplication budget."""
        if type(self.min_visits) is not int or not 2 <= self.min_visits <= MAX_VISITS:
            raise ValueError("min_visits must be an integer between 2 and 256")
        for interval in (self.window_seconds, self.refresh_seconds):
            if (
                type(interval) not in (int, float)
                or not math.isfinite(interval)
                or not MIN_GAP <= interval <= 86400
            ):
                raise ValueError("intervals must be between 0.25s and 1 day")


@dataclass
class Source:
    """One resolver's positive answer and next permitted background attempt."""

    value: rotation.Winner
    due: float | None


@dataclass
class Entry:
    """Contain one tracked name's LAN transactions and previously observed upstream refresh deadlines."""

    visits: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    latest: dict = field(default_factory=dict)
    hot: bool = False


@dataclass
class Fetch:
    """Track a single resolver transaction and whether a foreground caller needs it."""

    serial: int
    warm: bool
    entry: Entry | None
    demand: bool
    future: asyncio.Task | None = None


class History:
    """Count live LAN transactions and erase names without any visits inside the rolling window."""

    def __init__(self, config: Config, capacity: int = MAX_NAMES):
        """Initialize an empty bounded history; background activity never creates an entry."""
        self.config = config
        self.capacity = capacity
        self.entries = {}

    def count(self, key, now: float) -> int:
        """Discard visits at or before the cutoff, and return the current count."""
        entry = self.entries.get(key)
        if entry is None:
            return 0
        cutoff = now - self.config.window_seconds
        while entry.visits:
            first = next(iter(entry.visits))
            if entry.visits[first] > cutoff:
                break
            del entry.visits[first]
        return len(entry.visits)

    def prune(self, now: float):
        """End warm eligibility when the count falls below N and remove inactive names."""
        for key, entry in list(self.entries.items()):
            n = self.count(key, now)
            if entry.hot and n < self.config.min_visits:
                entry.hot = False
                rotation.log("warm-expired", domain=key[0], count=n)
            if not n:
                del self.entries[key]

    def record(self, key, token, now: float):
        """Record at most one timestamp per transport endpoint/transaction inside X; bounded overflow undercounts."""
        self.prune(now)
        entry = self.entries.get(key)
        if entry is None:
            if len(self.entries) >= self.capacity:
                cold = next((k for k, v in self.entries.items() if not v.hot), None)
                if cold is None:
                    return None
                del self.entries[cold]
            entry = self.entries[key] = Entry()
        new = token not in entry.visits and len(entry.visits) < MAX_VISITS
        if new:
            entry.visits[token] = now
        entry.hot = len(entry.visits) >= self.config.min_visits
        rotation.log("visit", domain=key[0], count=len(entry.visits), counted=new)
        return entry


class WarmCache(rotation.WinnerCache):
    """Reuse the rotation gateway and warm only recorded resolver contexts for recently frequent names."""

    def __init__(self, down: Path, config: Config, clock=monotonic):
        """Start bounded activity tracking, shared per-resolver lookups, and an empty job queue."""
        super().__init__(down)
        self.config = config
        self.clock = clock
        self.history = History(config)
        self.origin = contextvars.ContextVar("client-entry", default=None)
        self.channels = {}
        self.active_fetches = 0
        self.sequence = 0
        self.jobs = {}

    async def client_select(self, query, peer):
        """Record a genuine LAN request before resolving it; a hit preserves the existing refresh deadline."""
        key = (rotation.name(query), "A")
        entry = self.history.record(key, (*peer, query.id), self.clock())
        token = self.origin.set(entry)
        try:
            selected = await self.select(query)
            if (
                selected
                and self.history.entries.get(key) is entry
                and entry
                and selected.group not in entry.sources
            ):
                self.remember(key, selected, self.clock())
            return selected
        finally:
            self.origin.reset(token)

    async def select(self, query):
        """Bound storage of ordinary winners without adding flow-time lookups to LAN activity."""
        now = self.clock()
        for key, val in list(self.winners.items()):
            if val.expires <= now:
                self.winners.pop(key, None)
        domain = rotation.name(query)
        groups = self.allowed(query)
        entry = self.history.entries.get((domain, "A"))
        if entry and (domain, groups) not in self.winners:
            for src in entry.sources.values():
                candidate = src.value
                if candidate.group in groups and candidate.expires > now:
                    self.winners[domain, groups] = candidate
                    rotation.log(
                        "reuse-candidate",
                        domain=domain,
                        group=candidate.group,
                        ip=candidate.ip,
                    )
                    break
        try:
            return await super().select(query)
        finally:
            while len(self.winners) > MAX_NAMES * 4:
                self.winners.pop(next(iter(self.winners)))

    def remember(self, key, value, now):
        """Schedule an observed source at the earlier of Y or 80 percent of remaining TTL, with a minimum gap."""
        entry = self.history.entries.get(key)
        if entry is None:
            return
        domain = key[0]
        for view, current in list(self.winners.items()):
            if view[0] == domain and current.group == value.group:
                self.winners[view] = value
        ttl = value.expires - now
        entry.sources[value.group] = Source(
            value,
            None
            if ttl <= 0
            else now + max(MIN_GAP, min(self.config.refresh_seconds, 0.8 * ttl)),
        )

    async def fetch(self, query, group, background):
        """Merge overlapping warm/demand attempts per resolver; a late result cannot publish over a newer attempt."""
        key = (rotation.name(query), "A")
        if group not in self.allowed(query):
            return None, False
        chan = (key, group)
        active = self.channels.get(chan)
        if (
            active is None
            or active.future.done()
            or (not background and not active.warm)
        ):
            if self.active_fetches >= MAX_FETCHES:
                return None, False
            self.sequence += 1
            entry = self.history.entries.get(key)
            active = Fetch(self.sequence, background, entry, not background)
            active.future = asyncio.create_task(self.dispatch(query, group, active))
            self.channels[chan] = active
            self.active_fetches += 1
            if entry is not None:
                entry.latest[group] = active.serial
            active.future.add_done_callback(lambda task: self.finish_fetch(chan, task))
        elif not background:
            active.demand = True
        value = await asyncio.shield(active.future)
        entry = self.history.entries.get(key)
        valid = (
            entry is not None
            and entry.latest.get(group) == active.serial
            and group in self.allowed(query)
        )
        return value, valid

    async def dispatch(self, query, group, request):
        """Recheck the live entry and window inside the sending task; genuine joined demand can proceed independently."""
        if group not in self.allowed(query):
            return None
        if request.warm:
            key = (rotation.name(query), "A")
            entry = self.history.entries.get(key)
            eligible = (
                entry is not None
                and entry is request.entry
                and self.history.count(key, self.clock()) >= self.config.min_visits
                and group in entry.sources
                and entry.sources[group].due is not None
            )
            if eligible:
                rotation.log(
                    "warm-start", domain=key[0], group=group, count=len(entry.visits)
                )
            elif not request.demand:
                return None
        return await super().lookup(query, group)

    def finish_fetch(self, chan, task):
        """Release one upstream concurrency slot without disturbing a newer wave for the same resolver."""
        self.active_fetches -= 1
        active = self.channels.get(chan)
        if active is not None and active.future is task:
            self.channels.pop(chan)

    async def lookup(self, query, group):
        """Perform ordinary rotation arbitration and register a source only for the initiating LAN visit."""
        key = (rotation.name(query), "A")
        value, current = await self.fetch(query, group, False)
        entry = self.history.entries.get(key)
        if value and entry is not None:
            if not current:
                return None
            if self.origin.get() is entry or group in entry.sources:
                self.remember(key, value, self.clock())
        return value

    def tick(self):
        """Prune old visits and dispatch the earliest eligible jobs up to the global concurrency bound."""
        now = self.clock()
        self.history.prune(now)
        ready = []
        for key, entry in self.history.entries.items():
            if not entry.hot:
                continue
            query = dns.message.make_query(key[0], key[1])
            allowed = self.allowed(query)
            for group, src in entry.sources.items():
                due = src.due
                if (
                    group in allowed
                    and due is not None
                    and due <= now
                    and (key, group) not in self.jobs
                ):
                    ready.append((due, key, group))
        for _, key, group in sorted(ready)[: MAX_WARM_JOBS - len(self.jobs)]:
            job = asyncio.create_task(self.refresh_source(key, group))
            self.jobs[key, group] = job
            job.add_done_callback(lambda task, k=(key, group): self.finish_job(k, task))

    def finish_job(self, job_key, task):
        """Remove a finished refresh from the scheduler and expose unexpected background errors."""
        self.jobs.pop(job_key, None)
        if not task.cancelled() and task.exception():
            rotation.log(
                "warm-error",
                domain=job_key[0][0],
                group=job_key[1],
                error=str(task.exception()),
            )

    async def refresh_source(self, key, group):
        """Refresh one permitted recorded resolver without creating activity or prolonging stale winners."""
        now = self.clock()
        entry = self.history.entries.get(key)
        query = dns.message.make_query(key[0], key[1])
        allowed = self.allowed(query)
        if (
            entry is None
            or self.history.count(key, now) < self.config.min_visits
            or group not in allowed
            or group not in entry.sources
            or entry.sources[group].due is None
            or entry.sources[group].due > now
        ):
            return
        entry.sources[group].due = now + max(MIN_GAP, self.config.refresh_seconds)
        value, current = await self.fetch(query, group, True)
        now = self.clock()
        applied = False
        if (
            value
            and current
            and self.history.entries.get(key) is entry
            and self.history.count(key, now) >= self.config.min_visits
            and self.allowed(query) == allowed
        ):
            self.remember(key, value, now)
            applied = self.winners.get((key[0], allowed)) is value
        rotation.log(
            "warm-finish",
            domain=key[0],
            group=group,
            ip=value.ip if value else None,
            applied=applied,
            count=self.history.count(key, now),
        )

    async def schedule(self):
        """Run periodic checks on monotonic deadlines; each tick can only start jobs already present in history."""
        while True:
            self.tick()
            await asyncio.sleep(0.1)


async def main():
    """Run the opt-in lab gateway with strict threshold configuration and the existing FakeIP ports."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["gateway"])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--down", type=Path, default=Path("fi-down"))
    args = parser.parse_args()
    config = Config(**json.loads(args.config.read_text()))
    cache = WarmCache(args.down, config)
    task = asyncio.create_task(cache.schedule())
    try:
        await rotation.gateway(args.down, cache, cache.client_select)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
