"""OTP logic: storage, HMAC, send/verify limits, lockout, security journal.

All state lives in one process under one threading.Lock: check and update
happen atomically, so of N parallel verify calls with one valid code exactly
one succeeds. The plain code appears only in the outbox, never in storage or logs.
"""

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app import config, store
from app.store import Number

MSISDN_RE = re.compile(r"996[0-9]{9}")
CODE_RE = re.compile(r"[0-9]{6}")
BISHKEK = timezone(timedelta(hours=6))


def now() -> float:
    """The only clock. Tests replace it via monkeypatch."""
    return time.time()


@dataclass(frozen=True)
class Result:
    status: int
    detail: str
    retry_after: float | None = None

    @property
    def headers(self) -> dict[str, str]:
        if self.retry_after is None:
            return {}
        return {"Retry-After": str(max(1, math.ceil(self.retry_after)))}


_lock = threading.Lock()
_store = store.connect(config.REDIS_URL, lambda: now())  # lambda: tests replace now()
_numbers = getattr(_store, "numbers", None)  # in-memory mode only: lets tests inspect storage
_events: deque[dict] = deque(maxlen=config.EVENTS_KEEP)
# Totals since start: /events keeps only the last EVENTS_KEEP, so a pump of 429s
# would push everything else out. In memory in both modes: one worker.
_counts: Counter[str] = Counter()
_saved_som = 0.0
# A number key outlives every time-based state in it: send window, code TTL, lock.
# At least a day, so an expired code still answers 410 long after its TTL.
NUMBER_TTL = max(config.SEND_WINDOW, config.OTP_TTL, config.LOCK_SECONDS, 86400)


def reset() -> None:
    """Clear all state. For tests."""
    with _lock:
        global _saved_som
        _store.clear()
        _events.clear()
        _counts.clear()
        _saved_som = 0.0


def recent_events() -> list[dict]:
    with _lock:
        return list(reversed(_events))


def stats() -> dict:
    """Event counts by type and SMS money saved by refused sends, since start."""
    with _lock:
        return {"counts": dict(_counts), "saved_som": round(_saved_som, 2)}


def _hash(msisdn: str, code: str) -> bytes:
    return hmac.new(config.OTP_SECRET, (msisdn + code).encode(), hashlib.sha256).digest()


def _valid_msisdn(value: object) -> bool:
    return isinstance(value, str) and MSISDN_RE.fullmatch(value) is not None


def _valid_code(value: object) -> bool:
    return isinstance(value, str) and CODE_RE.fullmatch(value) is not None


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, BISHKEK).isoformat(timespec="seconds")


def _event(t: float, kind: str, msisdn: str | None = None, ip: str | None = None, **extra) -> None:
    """Security journal: never contains a code or its hash. Caller holds _lock."""
    global _saved_som
    event = {"ts": _iso(t), "type": kind, "msisdn": msisdn, "ip": ip, **extra}
    _events.append(event)
    _counts[kind] += 1
    _saved_som += extra.get("saved_som", 0.0)
    try:
        with config.SECURITY_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass  # the journal must not break the API


def _deliver(t: float, msisdn: str, code: str) -> None:
    """The SMS channel: the only place the plain code is written."""
    path = config.outbox_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": _iso(t), "msisdn": msisdn, "code": code})
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def _number(msisdn: str, t: float) -> Number:
    """State of the number with expired lock and old sends cleaned up.
    Caller holds _lock and saves it back with _save()."""
    n = _store.number(msisdn)
    if n.locked_until is not None and t >= n.locked_until:
        n.locked_until = None
        n.fails = 0
    n.sends = [s for s in n.sends if s[0] > t - config.SEND_WINDOW]
    return n


def _save(msisdn: str, n: Number) -> None:
    _store.save_number(msisdn, n, NUMBER_TTL)


def _locked(n: Number, t: float) -> bool:
    return n.locked_until is not None and t < n.locked_until


def _next_send_at(n: Number) -> float:
    """Earliest time the next send is allowed (n.sends is non-empty)."""
    last_t, last_ord = n.sends[-1]
    at = last_t + config.SEND_DELAYS[min(last_ord, len(config.SEND_DELAYS)) - 1]
    if len(n.sends) >= config.SEND_MAX:
        at = max(at, n.sends[len(n.sends) - config.SEND_MAX][0] + config.SEND_WINDOW)
    return at


def _ip_send_retry(ip: str, t: float) -> float | None:
    """Seconds until the IP may send again, None if allowed or the limit is off."""
    if not config.SEND_IP_MAX:
        return None
    sends = _store.timestamps("ipsend:" + ip)
    while sends and sends[0] <= t - config.SEND_IP_WINDOW:
        sends.popleft()
    if len(sends) < config.SEND_IP_MAX:
        return None
    return sends[0] + config.SEND_IP_WINDOW - t


def _rejected_send(t: float, kind: str, msisdn: str, ip: str) -> None:
    """A refused send is an SMS the business did not pay for."""
    _event(t, kind, msisdn, ip, saved_som=config.SMS_PRICE_SOM)


def send(msisdn: object, ip: str) -> Result:
    t = now()
    if not _valid_msisdn(msisdn):
        return Result(400, "invalid msisdn")
    with _lock:
        n = _number(msisdn, t)
        try:
            return _send(msisdn, ip, n, t)
        finally:
            _save(msisdn, n)


def _send(msisdn: str, ip: str, n: Number, t: float) -> Result:
    """Caller holds _lock and saves n."""
    if _locked(n, t):
        _rejected_send(t, "send_rejected_locked", msisdn, ip)
        return Result(423, "number is locked", n.locked_until - t)
    if n.sends:
        at = _next_send_at(n)
        if t < at:
            _rejected_send(t, "send_rejected_rate", msisdn, ip)
            return Result(429, "too many requests", at - t)
    retry = _ip_send_retry(ip, t)
    if retry is not None:
        _rejected_send(t, "send_rejected_ip", msisdn, ip)
        return Result(429, "too many requests from this ip", retry)
    code = f"{secrets.randbelow(10**6):06d}"
    # Deliver first: if the SMS channel fails, the old code and the send count stay
    # as they were, and the user may retry at once instead of waiting for a 429.
    try:
        _deliver(t, msisdn, code)
    except OSError:
        _event(t, "delivery_failed", msisdn, ip)
        return Result(503, "sms delivery failed")
    n.otp_hash, n.otp_created, n.otp_used = _hash(msisdn, code), t, False
    # The step only goes up while the window has sends; it resets once the window is empty.
    n.sends.append((t, n.sends[-1][1] + 1 if n.sends else 1))
    if config.SEND_IP_MAX:
        key = "ipsend:" + ip
        sends = _store.timestamps(key)
        sends.append(t)
        _store.save_timestamps(key, sends, config.SEND_IP_WINDOW)
    _event(t, "otp_sent", msisdn, ip)
    return Result(200, "sent")


def _ip_allowed(ip: str, t: float) -> bool:
    """Count every verify from the IP; rejected ones (429) are not counted."""
    key = "ip:" + ip
    hits = _store.timestamps(key)
    while hits and hits[0] <= t - config.IP_WINDOW:
        hits.popleft()
    if len(hits) >= config.IP_MAX:
        return False
    hits.append(t)
    _store.save_timestamps(key, hits, config.IP_WINDOW)
    return True


def verify(msisdn: object, code: object, ip: str) -> Result:
    t = now()
    with _lock:
        if not _ip_allowed(ip, t):
            # Only a valid msisdn goes to the journal: attacker strings of any size must not.
            _event(t, "verify_rejected_ip", msisdn if _valid_msisdn(msisdn) else None, ip)
            return Result(429, "too many requests from this ip")
        if not _valid_msisdn(msisdn) or not _valid_code(code):
            return Result(400, "invalid msisdn or code")
        n = _number(msisdn, t)
        try:
            return _verify(msisdn, code, ip, n, t)
        finally:
            _save(msisdn, n)


def _verify(msisdn: str, code: str, ip: str, n: Number, t: float) -> Result:
    """Caller holds _lock and saves n."""
    # Hash on every path: equal work whether or not the number has a code, so the
    # response time does not reveal an active OTP.
    candidate = _hash(msisdn, code)
    if _locked(n, t):
        return Result(423, "number is locked")
    if n.otp_hash is None:
        return Result(401, "no active code")
    if n.otp_used:
        _event(t, "verify_reused", msisdn, ip)  # a spent code again: a replay, not a typo
        return Result(401, "no active code")
    if t - n.otp_created >= config.OTP_TTL:
        return Result(410, "code expired")
    if hmac.compare_digest(n.otp_hash, candidate):
        n.otp_used, n.fails = True, 0
        _event(t, "verify_ok", msisdn, ip)
        return Result(200, "verified")
    n.fails += 1
    _event(t, "verify_failed", msisdn, ip, fails=n.fails)
    if n.fails >= config.VERIFY_MAX_FAILS:
        n.locked_until, n.otp_hash = t + config.LOCK_SECONDS, None
        _event(t, "number_locked", msisdn, ip, until=_iso(n.locked_until))
        return Result(423, "number is locked")
    return Result(401, "invalid code")
