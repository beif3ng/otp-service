"""scripts/attack.py against the app in-process: the jury attack of 1000 attempts never gets in.

TestClient is an httpx.Client, so the attacks run unchanged; one worker, fixed clock.
Every request comes from the TestClient IP; scripts/attack.py itself uses 127.0.0.1 and 127.0.0.2.
"""

import pytest

from scripts import attack
from tests.conftest import IP


@pytest.fixture
def client(api):
    return api.client(IP)


def run(fn, client, attempts=1000):
    lines: list[str] = []
    stopped = fn(client, attempts, 1, 0, lines.append)
    return stopped, "\n".join(lines)


def test_brute_one_number_locks_after_five_guesses(client):
    stopped, log = run(attack.brute, client)
    assert stopped
    # 4 x 401, the 5th wrong code -> 423 and lock, then 423 until the IP limit (20), then 429
    assert "verify responses: 401x4  423x16  429x980" in log
    assert "codes checked by the server: <= 5 of 1000, guessed: 0" in log


def test_spread_over_50_numbers_is_capped_by_ip_limit(client):
    stopped, log = run(attack.spread, client)
    assert stopped
    assert "send   responses: 200x50" in log
    assert "verify responses: 401x20  429x980" in log


def test_pump_sends_one_sms_per_number(client):
    stopped, log = run(attack.pump, client)
    assert stopped
    assert "send   responses: 200x50  429x950" in log
    assert "SMS sent: 50 of 1000, rejected: 950, saved at least 988.00 som" in log


def test_success_is_reported(client, codes, monkeypatch):
    """The verdict is not vacuous: a right guess makes the attack count as succeeded."""
    codes(123456)
    monkeypatch.setattr(attack, "guesses", lambda _: ["123456"])
    stopped, log = run(attack.brute, client)
    assert not stopped
    assert "ATTACK SUCCEEDED" in log
