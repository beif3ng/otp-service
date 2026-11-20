"""State storage: in-memory (default) or Redis with TTL (bonus, env REDIS_URL).

Both are used only under otp._lock in one uvicorn worker, so load -> check ->
save stays atomic. Redis keeps state across backend restarts and drops idle
keys by TTL; it stores the same data as memory: HMAC of the code, never the code.
"""

import json
import math
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

PREFIX = "otp:"


@dataclass
class Number:
    otp_hash: bytes | None = None
    otp_created: float = 0.0
    otp_used: bool = False
    fails: int = 0  # wrong codes; bound to the number, not to the OTP
    locked_until: float | None = None
    sends: list[tuple[float, int]] = field(default_factory=list)  # (time, ordinal in window)


class StoreUnavailable(Exception):
    """The storage backend (Redis) cannot be reached; the API answers 503."""


SWEEP_EVERY = 60.0  # s between sweeps of expired in-memory keys


class MemoryStore:
    """Objects are kept as is: changes are visible without save. TTL works as in
    Redis: every save refreshes it, an expired key reads as empty, and expired
    keys are swept so the dicts do not grow without bound."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self.numbers: dict[str, Number] = {}
        self.times: dict[str, deque[float]] = {}
        self._expires: dict[str, float] = {}  # "num:<msisdn>" or timestamps key -> expiry
        self._next_sweep = 0.0

    def _alive(self, key: str) -> bool:
        return self._expires.get(key, math.inf) > self._clock()

    def _touch(self, key: str, ttl: float) -> None:
        t = self._clock()
        self._expires[key] = t + ttl
        if t >= self._next_sweep:
            self._next_sweep = t + SWEEP_EVERY
            for k in [k for k, exp in self._expires.items() if exp <= t]:
                self._drop(k)

    def _drop(self, key: str) -> None:
        self._expires.pop(key, None)
        if key.startswith("num:"):
            self.numbers.pop(key[4:], None)
        else:
            self.times.pop(key, None)

    def number(self, msisdn: str) -> Number:
        if not self._alive("num:" + msisdn):
            self._drop("num:" + msisdn)
        return self.numbers.setdefault(msisdn, Number())

    def save_number(self, msisdn: str, n: Number, ttl: float) -> None:
        self.numbers[msisdn] = n
        self._touch("num:" + msisdn, ttl)

    def timestamps(self, key: str) -> deque[float]:
        if not self._alive(key):
            self._drop(key)
        return self.times.setdefault(key, deque())

    def save_timestamps(self, key: str, times: deque[float], ttl: float) -> None:
        self.times[key] = times
        self._touch(key, ttl)

    def clear(self) -> None:
        self.numbers.clear()
        self.times.clear()
        self._expires.clear()
        self._next_sweep = 0.0


class RedisStore:
    """JSON value per key; every save refreshes the key TTL."""

    def __init__(self, url: str) -> None:
        import redis  # only needed for the bonus

        # Calls run under otp._lock: without a timeout a stalled Redis hangs the whole API
        # instead of answering 503 (TimeoutError is a RedisError).
        self._r = redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
        self._errors = redis.RedisError
        self._r.ping()  # fail at startup, not on the first request

    def _get(self, key: str):
        try:
            raw = self._r.get(PREFIX + key)
        except self._errors as e:
            raise StoreUnavailable from e
        return None if raw is None else json.loads(raw)

    def _set(self, key: str, value, ttl: float) -> None:
        try:
            self._r.set(PREFIX + key, json.dumps(value), ex=max(1, math.ceil(ttl)))
        except self._errors as e:
            raise StoreUnavailable from e

    def number(self, msisdn: str) -> Number:
        data = self._get("num:" + msisdn)
        if data is None:
            return Number()
        return Number(
            otp_hash=bytes.fromhex(data["otp_hash"]) if data["otp_hash"] else None,
            otp_created=data["otp_created"],
            otp_used=data["otp_used"],
            fails=data["fails"],
            locked_until=data["locked_until"],
            sends=[(t, o) for t, o in data["sends"]],
        )

    def save_number(self, msisdn: str, n: Number, ttl: float) -> None:
        data = {
            "otp_hash": n.otp_hash.hex() if n.otp_hash else None,
            "otp_created": n.otp_created,
            "otp_used": n.otp_used,
            "fails": n.fails,
            "locked_until": n.locked_until,
            "sends": n.sends,
        }
        self._set("num:" + msisdn, data, ttl)

    def timestamps(self, key: str) -> deque[float]:
        return deque(self._get(key) or [])

    def save_timestamps(self, key: str, times: deque[float], ttl: float) -> None:
        self._set(key, list(times), ttl)

    def clear(self) -> None:
        for key in self._r.scan_iter(PREFIX + "*"):
            self._r.delete(key)


def connect(url: str | None, clock: Callable[[], float]) -> MemoryStore | RedisStore:
    return RedisStore(url) if url else MemoryStore(clock)
