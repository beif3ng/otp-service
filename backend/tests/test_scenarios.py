"""Replay the jury's open scenarios (scenarios_examples.json) exactly as written."""

import pytest

from scripts.scenarios import Runner, load


@pytest.mark.parametrize("scenario", load(), ids=lambda s: s["id"])
def test_jury_example(scenario, clock, api):
    assert Runner(clock, api.outbox, log=lambda _: None).run(scenario)
