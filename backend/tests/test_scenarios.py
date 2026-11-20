"""Replay scenario files in the jury format exactly as written.

scenarios_examples.json - the jury's open scenarios; scenarios_guess.json - our guesses
of the hidden ones, built from the spec and clarifications v1.1.
"""

from pathlib import Path

import pytest

from scripts.scenarios import InProcess, Runner, load

GUESS = Path(__file__).parent / "scenarios_guess.json"


@pytest.mark.parametrize("scenario", load() + load(GUESS), ids=lambda s: s["id"])
def test_scenario(scenario, clock, api):
    assert Runner(InProcess(clock), api.outbox, log=lambda _: None).run(scenario)
