"""POST /otp/send: format, delivery, delay steps, the 600 s window."""

import pytest

from app import config
from tests.conftest import MSISDN, OTHER_IP


@pytest.mark.parametrize(
    "msisdn",
    ["99677073000", "9967707300001", "997770730000", "99677073000a", " 996770730000", "", None, 996770730000],
)
def test_bad_msisdn_is_400(api, msisdn):
    r = api.send(msisdn)
    assert r.status_code == 400
    assert "detail" in r.json()
    assert api.deliveries() == []


@pytest.mark.parametrize("body", [b"not json", b"[]", b'"996770730000"', b"{}", b""])
def test_bad_body_is_400(api, body):
    r = api.client().post("/otp/send", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_send_delivers_code_to_outbox(api, codes):
    codes(42)
    assert api.send().status_code == 200
    assert api.deliveries() == [
        {"ts": "2026-11-21T09:00:00+06:00", "msisdn": MSISDN, "code": "000042"}
    ]


def test_o07_resend_before_30s_is_429_and_keeps_code(api, clock):
    """O07: send rejected at 29.999 s does not cancel the active code."""
    api.send()
    c1 = api.code()
    clock.advance(29.999)
    r = api.send()
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "1"
    assert len(api.deliveries()) == 1
    assert api.verify(c1).status_code == 200


def test_retry_after_on_429(api):
    api.send()
    r = api.send()
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "30"


def test_delay_steps_30_60_then_window_full(api, clock):
    assert api.send().status_code == 200  # 1st at 0
    clock.advance(30)
    assert api.send().status_code == 200  # 2nd at 30
    clock.advance(59.999)
    assert api.send().status_code == 429
    clock.advance(0.001)
    assert api.send().status_code == 200  # 3rd at 90
    clock.advance(120)
    r = api.send()  # 210: the 120 s step passed, but 3 sends are still in the window
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "390"  # until the 1st send leaves the window at 600
    clock.advance(389.999)
    assert api.send().status_code == 429  # 599.999: the 1st send is still in (t-600, t]
    clock.advance(0.001)
    assert api.send().status_code == 200  # 600: the 1st send left the window
    assert len(api.deliveries()) == 4


def test_step_resets_after_window_empties(api, clock):
    api.send()
    clock.advance(30)
    api.send()
    clock.advance(60)
    api.send()  # sends at 0, 30, 90
    clock.advance(600)  # 690: the window is empty
    assert api.send().status_code == 200
    clock.advance(29.999)
    assert api.send().status_code == 429
    clock.advance(0.001)
    assert api.send().status_code == 200  # back to the 30 s step


def test_step_holds_while_window_has_sends(api, clock):
    api.send()
    clock.advance(30)
    api.send()
    clock.advance(560)
    api.send()  # sends at 0, 30, 590
    clock.advance(119.999)  # 709.999: only the 3rd send is in the window, its 120 s step holds
    assert api.send().status_code == 429
    clock.advance(0.001)
    assert api.send().status_code == 200  # 4th at 710
    clock.advance(119.999)
    assert api.send().status_code == 429  # the step stays at 120 s, it does not fall back to 60 s
    clock.advance(0.001)
    assert api.send().status_code == 200  # 5th at 830


def test_new_send_cancels_previous_code(api, clock, codes):
    codes(111111, 222222)
    api.send()
    clock.advance(30)
    api.send()
    assert api.verify("111111").status_code == 401
    assert api.verify("222222").status_code == 200


def test_limits_are_per_number(api):
    assert api.send().status_code == 200
    assert api.send("996770730001").status_code == 200
    assert api.send("996770730002", ip=OTHER_IP).status_code == 200
    assert api.send().status_code == 429


def test_send_ip_limit_is_off_by_default(api):
    for i in range(50):
        assert api.send(f"99677073{i:04d}").status_code == 200


def test_send_ip_limit_when_enabled(api, clock, monkeypatch):
    monkeypatch.setattr(config, "SEND_IP_MAX", 3)
    for i in range(3):
        assert api.send(f"99677073{i:04d}").status_code == 200
    r = api.send("996770799999")
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "600"
    assert api.send("996770799999", ip=OTHER_IP).status_code == 200
    r = api.send(MSISDN)  # the number's own delay is checked before the IP limit
    assert (r.status_code, r.json()["detail"]) == (429, "too many requests")
    clock.advance(600)
    assert api.send("996770799998").status_code == 200


def test_rejected_send_is_saved_money(api, monkeypatch):
    monkeypatch.setattr(config, "SMS_PRICE_SOM", 2.5)
    api.send()
    api.send()
    events = api.client().get("/events").json()
    rejected = [e for e in events if e["type"] == "send_rejected_rate"]
    assert [e["saved_som"] for e in rejected] == [2.5]
    assert all("saved_som" not in e for e in events if e["type"] == "otp_sent")
