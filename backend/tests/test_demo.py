"""GET /demo: the login page of a made-up delivery service on top of the OTP API."""

import re
from pathlib import Path

from app import main, otp

SOURCES = Path(otp.__file__).read_text("utf-8") + Path(main.__file__).read_text("utf-8")


def test_demo_is_served(api):
    r = api.client().get("/demo")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "/otp/send" in r.text and "/otp/verify" in r.text


def test_every_api_error_has_a_message(api):
    """A new detail in the core must not reach the user as raw English."""
    details = set(re.findall(r'(?:Result\([45]\d\d, |\{"detail": )"([^"]+)"', SOURCES))
    assert details, "details not found in app/otp.py and app/main.py"
    page = api.client().get("/demo").text
    assert {d for d in details if f'"{d}":' not in page} == set()
