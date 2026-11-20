"""GET /stats: totals since start for the dashboard, unlike /events which keeps the last EVENTS_KEEP."""

from app import config, otp
from tests.conftest import MSISDN, wrong

OTHER = "996770730001"


def stats(api) -> dict:
    return api.client().get("/stats").json()


def test_counts_outlive_the_events_window(api):
    """A pump of 429s pushes everything else out of /events, but not out of /stats."""
    api.send()
    for _ in range(config.EVENTS_KEEP + 50):
        assert api.send().status_code == 429

    assert len(api.client().get("/events").json()) == config.EVENTS_KEEP
    s = stats(api)
    assert s["counts"] == {"otp_sent": 1, "send_rejected_rate": config.EVENTS_KEEP + 50}
    assert s["saved_som"] == round((config.EVENTS_KEEP + 50) * config.SMS_PRICE_SOM, 2)


def test_saved_som_sums_every_refused_send(api, monkeypatch):
    monkeypatch.setattr(config, "SMS_PRICE_SOM", 2.5)
    monkeypatch.setattr(config, "SEND_IP_MAX", 1)
    api.send()
    assert api.send().status_code == 429  # delay -> send_rejected_rate
    assert api.send(OTHER).status_code == 429  # per-IP send limit -> send_rejected_ip
    code = api.code()
    for _ in range(config.VERIFY_MAX_FAILS):
        api.verify(wrong(code))
    assert api.send().status_code == 423  # locked -> send_rejected_locked

    s = stats(api)
    for kind in ("send_rejected_rate", "send_rejected_ip", "send_rejected_locked"):
        assert s["counts"][kind] == 1
    assert s["counts"]["verify_failed"] == config.VERIFY_MAX_FAILS
    assert s["counts"]["number_locked"] == 1
    assert s["saved_som"] == 7.5  # only refused sends save money, verify events add nothing


def test_reset_clears_stats(api):
    api.send(MSISDN)
    otp.reset()
    assert stats(api) == {"counts": {}, "saved_som": 0.0}
