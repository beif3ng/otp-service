"""Attacks per 15 minutes over the last 24 h for the dashboard, read from the security journal.

/stats lives in memory and resets on every restart; the journal file survives it (on the VM
it sits in a volume). The file is read incrementally: each call parses only the lines
appended since the previous one.
"""

import json
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path

from app import config, otp

BUCKET_SECONDS = 900
BUCKETS = 96  # 24 h
SERIES = {
    "verify_failed": "brute",
    "verify_rejected_ip": "brute",
    "send_rejected_locked": "pumping",
    "send_rejected_rate": "pumping",
    "send_rejected_ip": "pumping",
}

_lock = threading.Lock()
_path: Path | None = None
_offset = 0
_counts: dict[int, Counter] = {}  # bucket start (Unix seconds) -> {"brute": n, "pumping": n}


def _read_new(path: Path) -> None:
    global _path, _offset
    if path != _path:
        _path, _offset = path, 0
        _counts.clear()
    try:
        if path.stat().st_size < _offset:  # the journal was truncated or replaced
            _offset = 0
            _counts.clear()
        with path.open("rb") as f:
            f.seek(_offset)
            data = f.read()
    except OSError:
        return  # no journal yet
    end = data.rfind(b"\n") + 1  # a line still being written is picked up next time
    _offset += end
    for line in data[:end].splitlines():
        try:
            event = json.loads(line)
            series = SERIES.get(event["type"])
            if series:
                t = datetime.fromisoformat(event["ts"]).timestamp()
                _counts.setdefault(int(t // BUCKET_SECONDS) * BUCKET_SECONDS, Counter())[series] += 1
        except (ValueError, KeyError, TypeError):
            continue  # a broken line must not break the dashboard


def history() -> dict:
    with _lock:
        _read_new(config.SECURITY_LOG)
        last = int(otp.now() // BUCKET_SECONDS) * BUCKET_SECONDS
        first = last - (BUCKETS - 1) * BUCKET_SECONDS
        for start in [s for s in _counts if s < first]:
            del _counts[start]
        buckets = []
        for start in range(first, last + BUCKET_SECONDS, BUCKET_SECONDS):
            c = _counts.get(start, Counter())
            ts = datetime.fromtimestamp(start, otp.BISHKEK).isoformat(timespec="seconds")
            buckets.append({"ts": ts, "brute": c["brute"], "pumping": c["pumping"]})
        return {"bucket_seconds": BUCKET_SECONDS, "buckets": buckets}
