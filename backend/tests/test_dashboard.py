"""GET /dashboard: the static page that polls /stats and /events."""

import re
from pathlib import Path

from app import otp

OTP_SOURCE = Path(otp.__file__).read_text("utf-8")


def test_dashboard_is_served(api):
    r = api.client().get("/dashboard")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "/stats" in r.text or '"stats"' in r.text


def test_every_event_type_has_a_label(api):
    """A new event type in the core must not show up on the dashboard as a raw name."""
    kinds = set(re.findall(r'_(?:event|rejected_send)\(t, "(\w+)"', OTP_SOURCE))
    assert kinds, "event types not found in app/otp.py"
    page = api.client().get("/dashboard").text
    assert {k for k in kinds if f"{k}:" not in page} == set()
