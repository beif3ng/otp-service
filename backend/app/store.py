"""State storage: in-memory (default) or Redis with TTL (bonus, env REDIS_URL).

Both are used only under otp._lock in one uvicorn worker, so load -> check ->
save stays atomic. Redis keeps state across backend restarts and drops idle
keys by TTL; it stores the same data as memory: HMAC of the code, never the code.
"""

import json
import math
from collections import deque
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


class MemoryStore:
    """Objects are kept as is: changes are visible without save, TTL is not needed."""

    def __init__(self) -> None:
        self.numbers: dict[str, Number] = {}
        self.times: dict[str, deque[float]] = {}

    def number(self, msisdn: str) -> Number:
        return self.numbers.setdefault(msisdn, Number())

    def save_number(self, msisdn: str, n: Number, ttl: float) -> None:
        pass

    def timestamps(self, key: str) -> deque[float]:
        return self.times.setdefault(key, deque())

    def save_timestamps(self, key: str, times: deque[float], ttl: float) -> None:
        pass

    def clear(self) -> None:
        self.numbers.clear()
        self.times.clear()


class RedisStore:
    """JSON value per key; every save refreshes the key TTL."""

    def __init__(self, url: str) -> None:
        import redis  # only needed for the bonus

        self._r = redis.Redis.from_url(url)
        self._r.ping()  # fail at startup, not on the first request

    def _get(self, key: str):
        raw = self._r.get(PREFIX + key)
        return None if raw is None else json.loads(raw)

    def _set(self, key: str, value, ttl: float) -> None:
        self._r.set(PREFIX + key, json.dumps(value), ex=max(1, math.ceil(ttl)))

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


def connect(url: str | None) -> MemoryStore | RedisStore:
    return RedisStore(url) if url else MemoryStore()
