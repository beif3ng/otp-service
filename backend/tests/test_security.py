"""Only the outbox sees the plain code: storage keeps an HMAC, the journal keeps neither."""

import hashlib
import hmac

from app import config, otp
from tests.conftest import MSISDN, wrong

CODE = 314159  # does not occur in MSISDN or timestamps, so a substring search is reliable


def test_storage_keeps_only_hmac(api, codes):
    codes(CODE)
    api.send()
    stored = otp._numbers[MSISDN]
    assert stored.otp_hash == hmac.new(config.OTP_SECRET, f"{MSISDN}{CODE}".encode(), hashlib.sha256).digest()
    assert str(CODE) not in repr(stored)


def test_journal_and_events_have_no_code(api, codes):
    codes(CODE)
    api.send()
    api.verify(wrong(str(CODE)))
    api.verify(str(CODE))
    digest = otp._numbers[MSISDN].otp_hash.hex()

    log = config.SECURITY_LOG.read_text("utf-8")
    events = api.client().get("/events")
    assert events.status_code == 200
    for text in (log, events.text):
        assert str(CODE) not in text
        assert wrong(str(CODE)) not in text
        assert digest not in text


def test_events_record_security_actions(api, clock):
    api.send()
    for _ in range(5):
        api.verify(wrong(api.code()))
    api.send()
    for _ in range(16):
        api.verify("bad")
    types = {e["type"] for e in api.client().get("/events").json()}
    assert {"otp_sent", "verify_failed", "number_locked", "send_rejected_locked", "verify_rejected_ip"} <= types


def test_reused_code_is_journaled(api):
    """A spent code sent again is a replay: 401 as before, and the dashboard sees it."""
    api.send()
    code = api.code()
    assert api.verify(code).status_code == 200
    assert api.verify(code).status_code == 401
    other = "000000" if code != "000000" else "000001"
    assert api.verify(other).status_code == 401  # another code after login: not a replay
    assert api.verify("123456", msisdn="996770730001").status_code == 401  # never sent: not a replay
    events = api.client().get("/events").json()
    assert sum(e["type"] == "verify_reused" for e in events) == 1


def test_no_public_way_to_read_code(api):
    paths = set(api.client().get("/openapi.json").json()["paths"])
    # /stats/history returns only counts per 15 minutes
    assert paths == {"/otp/send", "/otp/verify", "/events", "/stats", "/stats/history"}
