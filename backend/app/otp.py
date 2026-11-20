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
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app import config

MSISDN_RE = re.compile(r"996[0-9]{9}")
CODE_RE = re.compile(r"[0-9]{6}")
BISHKEK = timezone(timedelta(hours=6))


def now() -> float:
    """The only clock. Tests replace it via monkeypatch."""
    return time.time()


@dataclass
class Result:
    status: int
    detail: str
    retry_after: float | None = None

    @property
    def headers(self) -> dict[str, str]:
        if self.retry_after is None:
            return {}
        return {"Retry-After": str(max(1, math.ceil(self.retry_after)))}


@dataclass
class Number:
    otp_hash: bytes | None = None
    otp_created: float = 0.0
    otp_used: bool = False
    fails: int = 0  # wrong codes; bound to the number, not to the OTP
    locked_until: float | None = None
    sends: list[tuple[float, int]] = field(default_factory=list)  # (time, ordinal in window)


_lock = threading.Lock()
_numbers: dict[str, Number] = {}
_ip_hits: dict[str, deque[float]] = {}
_ip_sends: dict[str, deque[float]] = {}
_events: deque[dict] = deque(maxlen=config.EVENTS_KEEP)


def reset() -> None:
    """Clear all state. For tests."""
    with _lock:
        _numbers.clear()
        _ip_hits.clear()
        _ip_sends.clear()
        _events.clear()


def recent_events() -> list[dict]:
    with _lock:
        return list(reversed(_events))


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
    event = {"ts": _iso(t), "type": kind, "msisdn": msisdn, "ip": ip, **extra}
    _events.append(event)
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
    """State of the number with expired lock and old sends cleaned up."""
    n = _numbers.setdefault(msisdn, Number())
    if n.locked_until is not None and t >= n.locked_until:
        n.locked_until = None
        n.fails = 0
    n.sends = [s for s in n.sends if s[0] > t - config.SEND_WINDOW]
    return n


def _locked(n: Number, t: float) -> bool:
    return n.locked_until is not None and t < n.locked_until


def _next_send_at(n: Number) -> float:
    """Earliest time the next send is allowed (n.sends is non-empty)."""
    last_t, last_ord = n.sends[-1]
    at = last_t + config.SEND_DELAYS[min(last_ord, len(config.SEND_DELAYS)) - 1]
    if len(n.sends) >= config.SEND_MAX:
        at = max(at, n.sends[len(n.sends) - config.SEND_MAX][0] + config.SEND_WINDOW)
    return at


def _ip_send_retry(ip: str | None, t: float) -> float | None:
    """Seconds until the IP may send again, None if allowed or the limit is off."""
    if not config.SEND_IP_MAX or ip is None:
        return None
    sends = _ip_sends.setdefault(ip, deque())
    while sends and sends[0] <= t - config.SEND_IP_WINDOW:
        sends.popleft()
    if len(sends) < config.SEND_IP_MAX:
        return None
    return sends[0] + config.SEND_IP_WINDOW - t


def _rejected_send(t: float, kind: str, msisdn: str, ip: str | None) -> None:
    """A refused send is an SMS the business did not pay for."""
    _event(t, kind, msisdn, ip, saved_som=config.SMS_PRICE_SOM)


def send(msisdn: object, ip: str | None) -> Result:
    t = now()
    if not _valid_msisdn(msisdn):
        return Result(400, "invalid msisdn")
    with _lock:
        n = _number(msisdn, t)
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
        n.otp_hash, n.otp_created, n.otp_used = _hash(msisdn, code), t, False
        n.sends.append((t, len(n.sends) + 1))
        if config.SEND_IP_MAX and ip is not None:
            _ip_sends[ip].append(t)
        _deliver(t, msisdn, code)
        _event(t, "otp_sent", msisdn, ip)
    return Result(200, "sent")


def _ip_allowed(ip: str, t: float) -> bool:
    """Count every verify from the IP; rejected ones (429) are not counted."""
    hits = _ip_hits.setdefault(ip, deque())
    while hits and hits[0] <= t - config.IP_WINDOW:
        hits.popleft()
    if len(hits) >= config.IP_MAX:
        return False
    hits.append(t)
    return True


def verify(msisdn: object, code: object, ip: str) -> Result:
    t = now()
    with _lock:
        if not _ip_allowed(ip, t):
            _event(t, "verify_rejected_ip", msisdn if isinstance(msisdn, str) else None, ip)
            return Result(429, "too many requests from this ip")
        if not _valid_msisdn(msisdn) or not _valid_code(code):
            return Result(400, "invalid msisdn or code")
        n = _number(msisdn, t)
        if _locked(n, t):
            return Result(423, "number is locked")
        if n.otp_hash is None or n.otp_used:
            return Result(401, "no active code")
        if t - n.otp_created >= config.OTP_TTL:
            return Result(410, "code expired")
        if hmac.compare_digest(n.otp_hash, _hash(msisdn, code)):
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
