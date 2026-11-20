"""GET /stats/history: attacks per 15 minutes over 24 h, read from the security journal."""

import json

from app import config, otp
from tests.conftest import MSISDN, wrong


def get(api) -> dict:
    return api.client().get("/stats/history").json()


def last(api) -> dict:
    return get(api)["buckets"][-1]


def test_shape_is_96_buckets_of_15_minutes_ending_now(api):
    h = get(api)
    assert h["bucket_seconds"] == 900
    assert len(h["buckets"]) == 96
    assert h["buckets"][-1] == {"ts": "2026-11-21T09:00:00+06:00", "brute": 0, "pumping": 0}
    assert h["buckets"][0]["ts"] == "2026-11-20T09:15:00+06:00"


def test_counts_brute_force_and_pumping(api):
    api.send()
    code = api.code()
    for _ in range(3):
        assert api.verify(wrong(code)).status_code == 401
    for _ in range(2):
        assert api.send().status_code == 429
    assert last(api) == {"ts": "2026-11-21T09:00:00+06:00", "brute": 3, "pumping": 2}


def test_reads_only_new_lines_on_each_call(api):
    api.send()
    assert last(api)["pumping"] == 0
    api.send()
    assert last(api)["pumping"] == 1
    api.send()
    assert last(api)["pumping"] == 2


def test_survives_restart_because_it_reads_the_journal(api):
    api.send()
    api.send()
    otp.reset()  # memory is gone, the journal file stays
    assert otp.stats()["counts"] == {}
    assert last(api)["pumping"] == 1


def test_events_move_to_older_buckets_and_drop_after_24_hours(api, clock):
    api.send()
    api.send()
    clock.advance(900)
    h = get(api)["buckets"]
    assert (h[-2]["pumping"], h[-1]["pumping"]) == (1, 0)
    clock.advance(24 * 3600)
    assert all(b["pumping"] == 0 for b in get(api)["buckets"])


def test_existing_journal_is_read_from_the_start(api, tmp_path, monkeypatch):
    log = tmp_path / "old.log"
    lines = [
        {"ts": "2026-11-21T08:50:00+06:00", "type": "verify_rejected_ip", "msisdn": None, "ip": "x"},
        {"ts": "2026-11-21T08:51:00+06:00", "type": "otp_sent", "msisdn": MSISDN, "ip": "x"},
    ]
    log.write_text("".join(json.dumps(e) + "\n" for e in lines) + "not json\n[1]\n", "utf-8")
    monkeypatch.setattr(config, "SECURITY_LOG", log)
    h = get(api)["buckets"]
    assert h[-2] == {"ts": "2026-11-21T08:45:00+06:00", "brute": 1, "pumping": 0}


def test_unfinished_last_line_waits_for_its_newline(api, tmp_path, monkeypatch):
    log = tmp_path / "partial.log"
    line = json.dumps({"ts": "2026-11-21T09:00:01+06:00", "type": "verify_failed"})
    log.write_text(line[:20], "utf-8")
    monkeypatch.setattr(config, "SECURITY_LOG", log)
    assert last(api)["brute"] == 0
    log.write_text(line + "\n", "utf-8")
    assert last(api)["brute"] == 1


def test_missing_journal_gives_empty_history(api, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SECURITY_LOG", tmp_path / "nope.log")
    assert all(b["brute"] == b["pumping"] == 0 for b in get(api)["buckets"])
