"""Red team fixes: bad input, journal flooding, delivery and storage failures,
idle numbers forgotten, env validation."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from app import config, otp, store
from tests.conftest import IP, MSISDN, wrong

BACKEND = Path(__file__).resolve().parents[1]
DEEP_JSON = "[" * 100_000 + "]" * 100_000


def test_deeply_nested_json_is_400(api):
    c = api.client()
    assert c.post("/otp/send", content=DEEP_JSON).status_code == 400
    assert c.post("/otp/verify", content=DEEP_JSON).status_code == 400


def test_deeply_nested_json_counts_in_ip_limit(api):
    c = api.client()
    for _ in range(config.IP_MAX):
        assert c.post("/otp/verify", content=DEEP_JSON).status_code == 400
    assert c.post("/otp/verify", content=DEEP_JSON).status_code == 429


def test_huge_body_is_400_and_counts_in_ip_limit(api):
    """A body over MAX_BODY is not parsed: 400, and verify still counts in the IP limit."""
    c = api.client()
    huge = b'{"msisdn": "' + b"9" * 10**6 + b'"}'
    assert c.post("/otp/send", content=huge).status_code == 400
    for _ in range(config.IP_MAX):
        assert c.post("/otp/verify", content=huge).status_code == 400
    assert c.post("/otp/verify", content=huge).status_code == 429


def test_ip_rejection_does_not_journal_junk_msisdn(api):
    for _ in range(config.IP_MAX):
        api.verify("000000")
    assert api.verify("000000", msisdn="A" * 5000).status_code == 429
    event = otp.recent_events()[0]
    assert event["type"] == "verify_rejected_ip"
    assert event["msisdn"] is None
    assert "A" * 100 not in config.SECURITY_LOG.read_text("utf-8")


def test_ip_rejection_journals_valid_msisdn(api):
    for _ in range(config.IP_MAX):
        api.verify("000000")
    api.verify("000000")
    assert otp.recent_events()[0]["msisdn"] == MSISDN


def test_failed_delivery_is_503_and_not_counted(api, clock, monkeypatch, tmp_path):
    assert api.send().status_code == 200
    old = api.code()
    clock.advance(config.SEND_DELAYS[0])
    monkeypatch.setenv("OTP_OUTBOX", str(tmp_path))  # a directory: write fails
    r = api.send()
    assert r.status_code == 503
    assert otp.recent_events()[0]["type"] == "delivery_failed"
    # Nothing changed: the old code still works, the failed send did not count.
    assert api.verify(old).status_code == 200


def test_send_after_failed_delivery_is_not_delayed(api, monkeypatch, tmp_path):
    good = str(tmp_path / "outbox" / "sms.jsonl")
    monkeypatch.setenv("OTP_OUTBOX", str(tmp_path))
    assert api.send().status_code == 503
    monkeypatch.setenv("OTP_OUTBOX", good)
    assert api.send().status_code == 200  # not 429: the failed send was not counted


def test_storage_unavailable_is_503(api, monkeypatch):
    def down(*_):
        raise store.StoreUnavailable

    monkeypatch.setattr(otp._store, "number", down)
    r = api.send()
    assert r.status_code == 503
    assert r.json() == {"detail": "storage unavailable"}


def test_idle_number_forgets_fails(api, clock):
    """Same as the Redis TTL: a number idle for NUMBER_TTL is forgotten entirely."""
    api.send()
    code = api.code()
    for _ in range(config.VERIFY_MAX_FAILS - 1):
        assert api.verify(wrong(code)).status_code == 401
    clock.advance(otp.NUMBER_TTL)
    api.send()
    code = api.code()
    assert api.verify(wrong(code)).status_code == 401  # fails restarted at 1


def test_active_number_keeps_fails(api, clock):
    api.send()
    code = api.code()
    for _ in range(config.VERIFY_MAX_FAILS - 1):
        assert api.verify(wrong(code)).status_code == 401
    clock.advance(otp.NUMBER_TTL - 1)
    api.send()
    code = api.code()
    assert api.verify(wrong(code)).status_code == 423


def test_idle_numbers_are_swept(api, clock):
    for i in range(100):
        otp.send(f"99677000{i:04d}", IP)
    clock.advance(otp.NUMBER_TTL + store.SWEEP_EVERY)
    otp.send(MSISDN, IP)
    assert list(otp._numbers) == [MSISDN]


@pytest.mark.parametrize("value", ["abc", "-1", "nan", "inf"])
def test_bad_env_number_stops_start(monkeypatch, value):
    monkeypatch.setenv("OTP_TTL", value)
    with pytest.raises(SystemExit, match="OTP_TTL"):
        config._num("OTP_TTL", 120)


@pytest.mark.parametrize("name", ["OTP_TTL", "SEND_WINDOW", "LOCK_SECONDS", "IP_WINDOW", "SEND_IP_WINDOW"])
def test_zero_window_stops_start(name):
    """0 would turn the protection off: IP_WINDOW=0 never limits, LOCK_SECONDS=0 never locks.
    A fresh process imports the real config, so a setting that lost positive=True fails here."""
    env = {k: v for k, v in os.environ.items() if k != "REDIS_URL"} | {name: "0"}
    cmd = [sys.executable, "-c", "import app.config"]
    r = subprocess.run(cmd, check=False, cwd=BACKEND, env=env, capture_output=True, text=True)  # failing is the point
    assert r.returncode != 0
    assert f"env {name}='0'" in r.stderr


@pytest.mark.parametrize("value", ["0", "20.9"])
def test_bad_env_count_stops_start(monkeypatch, value):
    monkeypatch.setenv("SEND_MAX", value)
    with pytest.raises(SystemExit, match="SEND_MAX"):
        config._int("SEND_MAX", 3, minimum=1)


def test_redis_without_stable_key_stops_start(monkeypatch):
    monkeypatch.setattr(config, "REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.delenv("OTP_SECRET", raising=False)
    monkeypatch.delenv("OTP_SECRET_FILE", raising=False)
    with pytest.raises(SystemExit, match="OTP_SECRET"):
        config._otp_secret()
