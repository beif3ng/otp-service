"""Shared fixtures: fake clock, isolated outbox and journal, HTTP helpers.

Every test starts with empty state at a fixed moment; time moves only via clock.advance().
"""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config, otp
from app.main import app

MSISDN = "996770730000"
IP = "192.0.2.10"
OTHER_IP = "198.51.100.20"
START = datetime(2026, 11, 21, 3, 0, tzinfo=UTC).timestamp()  # 09:00 in Bishkek


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class Api:
    """Talks to the app over HTTP like the jury does; reads codes from the outbox."""

    def __init__(self, outbox: Path) -> None:
        self.outbox = outbox
        self._clients: dict[str, TestClient] = {}

    def client(self, ip: str = IP) -> TestClient:
        if ip not in self._clients:
            self._clients[ip] = TestClient(app, client=(ip, 50000))
        return self._clients[ip]

    def send(self, msisdn: object = MSISDN, ip: str = IP):
        return self.client(ip).post("/otp/send", json={"msisdn": msisdn})

    def verify(self, code: object, msisdn: object = MSISDN, ip: str = IP):
        return self.client(ip).post("/otp/verify", json={"msisdn": msisdn, "code": code})

    def deliveries(self) -> list[dict]:
        if not self.outbox.exists():
            return []
        return [json.loads(line) for line in self.outbox.read_text("utf-8").splitlines()]

    def code(self, msisdn: str = MSISDN) -> str:
        """capture_delivery: the last outbox line for the number."""
        return [d for d in self.deliveries() if d["msisdn"] == msisdn][-1]["code"]


def wrong(code: str) -> str:
    """A valid-format code that differs from the given one."""
    return f"{(int(code) + 1) % 10**6:06d}"


@pytest.fixture(autouse=True)
def clock(monkeypatch, tmp_path) -> Clock:
    monkeypatch.setenv("OTP_OUTBOX", str(tmp_path / "outbox" / "sms.jsonl"))
    monkeypatch.setattr(config, "SECURITY_LOG", tmp_path / "security.log")
    c = Clock(START)
    monkeypatch.setattr(otp, "now", c)
    otp.reset()
    return c


@pytest.fixture
def api(tmp_path) -> Api:
    return Api(tmp_path / "outbox" / "sms.jsonl")


@pytest.fixture
def codes(monkeypatch):
    """Controlled code source: codes(111111, 222222) makes sends issue these codes in order."""

    def use(*values: int) -> None:
        it = iter(values)
        monkeypatch.setattr(otp.secrets, "randbelow", lambda _: next(it))

    return use
