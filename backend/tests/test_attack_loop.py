"""scripts/attack_loop.py against the app in-process: random rounds never get in."""

import random

from scripts import attack_loop
from tests.conftest import IP


def test_random_rounds_are_all_stopped(api):
    random.seed(6)
    client = api.client(IP)
    lines: list[str] = []
    played, succeeded = attack_loop.loop(lambda source: client, (60, 120), 1, (0, 0), lines.append, rounds=6)
    assert played.total() == 6
    assert succeeded == 0
    assert "ATTACK SUCCEEDED" not in "\n".join(lines)
