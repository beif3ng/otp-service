"""Replay jury scenarios (scenarios_examples.json format) and log every step.

Two modes:
- default: in-process with a fake clock, `advance 120` is instant. Shows the number state too.
- --live: a fresh uvicorn process per scenario, real HTTP, real seconds, real outbox file.
  All requests come from 127.0.0.1 (a real connection cannot fake client_ip).
  Timing precision is about ±1 ms, so a step 1 ms before a boundary (O07: 29.999 s)
  is a coin flip here; exact boundaries are checked by the fake clock (default mode, pytest).

Per step it prints the request, the response against the expectation, the SMS from the
outbox and new security events.

Usage, from backend/:
    uv run python scripts/scenarios.py              # all scenarios, fake clock
    uv run python scripts/scenarios.py O12 O16      # selected ones
    uv run python scripts/scenarios.py --live       # real time, ~3 min
    uv run python scripts/scenarios.py --file tests/scenarios_guess.json  # our guesses
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import warnings
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))  # make `app` importable when run as a script
warnings.filterwarnings("ignore", message="Using `httpx`")  # starlette TestClient notice

import httpx
from fastapi.testclient import TestClient

from app import config, otp
from app.main import app

SCENARIOS = BACKEND / "tests" / "scenarios_examples.json"
START = datetime.fromisoformat("2026-11-20T12:00:00+06:00").timestamp()  # test_identities.json
SEND_IP = "192.0.2.10"  # jury send steps have no client_ip
PAD = " " * 12

Log = Callable[[str], None]


class Clock:
    def __init__(self) -> None:
        self.t = START

    def __call__(self) -> float:
        return self.t


class InProcess:
    """The app in this process, fake clock; client_ip is honored."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self._clients: dict[str, TestClient] = {}

    def begin(self) -> None:
        otp.reset()
        self.clock.t = START

    def end(self) -> None:
        pass

    def elapsed(self) -> str:
        return f"+{self.clock.t - START:8.3f}s"

    def advance(self, seconds: float) -> None:
        self.clock.t += seconds

    def call(self, method: str, path: str, body: dict, ip: str) -> tuple[str, httpx.Response]:
        if ip not in self._clients:
            self._clients[ip] = TestClient(app, client=(ip, 50000))
        return ip, self._clients[ip].request(method, path, json=body)

    def events(self) -> list[dict]:
        return list(otp._events)

    def state(self, msisdn: object) -> str | None:
        """The number as the service sees it. No code and no hash: only their status."""
        n = otp._numbers.get(msisdn) if isinstance(msisdn, str) else None
        if n is None:
            return "no state"
        t = self.clock.t
        if n.otp_hash is None:
            code = "none"
        elif n.otp_used:
            code = "used"
        elif t - n.otp_created >= config.OTP_TTL:
            code = f"expired (issued {t - n.otp_created:.3f}s ago)"
        else:
            code = f"active, {config.OTP_TTL - (t - n.otp_created):.3f}s left"
        lock = f"{n.locked_until - t:.3f}s left" if n.locked_until and t < n.locked_until else "no"
        sends = ", ".join(f"#{o} at +{s - START:.3f}s" for s, o in n.sends) or "-"
        return f"code={code} | fails={n.fails} | lock={lock} | sends in window: {sends}"


class Live:
    """A fresh uvicorn process per scenario (fresh state, like the jury stand), real seconds.

    The server reads its clock somewhere inside a request, so a request is placed by its
    midpoint: time zero is the midpoint of the first request, and a step after `advance`
    total S is timed so that its midpoint lands at S. One keep-alive connection keeps the
    uncertainty (half the request time) around a millisecond.
    """

    def __init__(self, outbox: Path, security_log: Path) -> None:
        self.env = {**os.environ, "OTP_OUTBOX": str(outbox), "SECURITY_LOG": str(security_log)}
        self.proc: subprocess.Popen | None = None

    def begin(self) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"],
            cwd=BACKEND, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 20
        while True:
            try:
                httpx.get(f"{self.base}/events", timeout=1)
                break
            except httpx.TransportError as exc:
                if self.proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("uvicorn did not start") from exc
                time.sleep(0.1)
        self.client = httpx.Client(base_url=self.base, timeout=30)
        self.client.get("/events")  # open the keep-alive connection before timing starts
        self.anchor: float | None = None
        self.offset = self.real = self.half = 0.0

    def end(self) -> None:
        if self.proc:
            self.client.close()
            self.proc.terminate()
            self.proc.wait()

    def elapsed(self) -> str:
        return f"+{self.offset:8.3f}s | real +{self.real:8.3f}s ±{self.half * 1000:.1f}ms"

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def call(self, method: str, path: str, body: dict, ip: str) -> tuple[str, httpx.Response]:
        if self.anchor is not None:
            target = self.anchor + self.offset
            if target - time.perf_counter() > 0.2:
                # After a long idle the first request is slow (±7 ms): wake the connection,
                # then time a second, warm request to estimate the latency.
                time.sleep(target - time.perf_counter() - 0.1)
                self.client.get("/events")
                w = time.perf_counter()
                self.client.get("/events")
                self.half = (time.perf_counter() - w) / 2
            while time.perf_counter() < target - self.half:  # spin: sleep() is not that precise
                pass
        t1 = time.perf_counter()  # not monotonic(): it ticks 15.6 ms on Windows
        r = self.client.request(method, path, json=body)
        t2 = time.perf_counter()
        if self.anchor is None:
            self.anchor = (t1 + t2) / 2
        self.real, self.half = (t1 + t2) / 2 - self.anchor, (t2 - t1) / 2
        return "127.0.0.1", r

    def events(self) -> list[dict]:
        return list(reversed(self.client.get("/events").json()))

    def state(self, msisdn: object) -> str | None:
        return None  # internals live in another process


def load(path: Path = SCENARIOS) -> list[dict]:
    return json.loads(path.read_text("utf-8"))


def _resolve(value: object, bound: dict[str, str]) -> object:
    """$c1 -> captured code, $wrong:c1 -> a different 6-digit code."""
    if not isinstance(value, str) or not value.startswith("$"):
        return value
    if value.startswith("$wrong:"):
        return f"{(int(bound[value[7:]]) + 1) % 10**6:06d}"
    return bound[value[1:]]


class Runner:
    def __init__(self, transport: InProcess | Live, outbox: Path, log: Log = print) -> None:
        self.tr, self.outbox, self.log = transport, outbox, log

    def _call(self, req: dict, bound: dict[str, str]) -> tuple[dict, str, httpx.Response]:
        body = {k: _resolve(v, bound) for k, v in req.get("body", {}).items()}
        ip, r = self.tr.call(req["method"], req["path"], body, req.get("client_ip", SEND_IP))
        return body, ip, r

    def _deliveries(self) -> list[dict]:
        if not self.outbox.exists():
            return []
        return [json.loads(line) for line in self.outbox.read_text("utf-8").splitlines()]

    def run(self, scenario: dict) -> bool:
        self.outbox.unlink(missing_ok=True)
        self.log(f"\n=== {scenario['id']}  {scenario['title']}")
        if scenario.get("overrides"):
            self.log(f"{PAD}! overrides ignored: {scenario['overrides']}")
        self.bound: dict[str, str] = {}  # $c1 etc., shared between steps
        self.tr.begin()
        try:
            ok = True
            for step in scenario["steps"]:
                ok &= self._step(step)
        finally:
            self.tr.end()
        self.log(f"=== {scenario['id']}: {'PASS' if ok else 'FAIL'}")
        return ok

    def _step(self, step: dict) -> bool:
        bound = self.bound
        seen_sms, seen_events = len(self._deliveries()), len(self.tr.events())
        op = step["op"]
        msisdn = None

        if op == "request":
            body, ip, r = self._call(step, bound)
            prefix = f"[{self.tr.elapsed()}]"
            msisdn = body.get("msisdn")
            want = step["expected"]["status"]
            retry = f" Retry-After={r.headers['Retry-After']}" if "Retry-After" in r.headers else ""
            passed = r.status_code == want
            self.log(f"{prefix} {step['method']} {step['path']} {json.dumps(body)} ip={ip}")
            self.log(f"{PAD}-> {r.status_code} {r.json().get('detail')}{retry}"
                     f"   expected {want}  {'OK' if passed else 'FAIL'}")
        elif op == "capture_delivery":
            msisdn = step["msisdn"]
            mine = [d for d in self._deliveries() if d["msisdn"] == msisdn]
            passed = bool(mine)
            if mine:
                bound[step["bind"]] = mine[-1]["code"]
                self.log(f"[{self.tr.elapsed()}] capture_delivery {msisdn}: ${step['bind']} = {mine[-1]['code']}")
            else:
                self.log(f"[{self.tr.elapsed()}] capture_delivery {msisdn}: no SMS  FAIL")
        elif op == "advance":
            self.tr.advance(step["seconds"])
            passed = True
            self.log(f"[{self.tr.elapsed()}] advance {step['seconds']}s")
        elif op == "parallel":
            reqs = step["requests"]
            with ThreadPoolExecutor(len(reqs)) as pool:
                results = list(pool.map(lambda req: self._call(req, bound), reqs))
            msisdn = results[0][0].get("msisdn")
            got = Counter(str(r.status_code) for _, _, r in results)
            exp = step["expected"]
            passed = len(results) == exp.get("count", len(results)) and got == Counter(exp["status_counts"])
            first = reqs[0]
            self.log(f"[{self.tr.elapsed()}] parallel x{len(reqs)}: {first['method']} {first['path']} "
                     f"{json.dumps(results[0][0])} ip={results[0][1]}")
            self.log(f"{PAD}-> {dict(sorted(got.items()))}   expected {exp['status_counts']}  "
                     f"{'OK' if passed else 'FAIL'}")
        else:
            raise ValueError(f"unknown op: {op}")

        for d in self._deliveries()[seen_sms:]:
            self.log(f"{PAD}SMS   {d['msisdn']}: {d['code']}  (ts {d['ts']})")
        new = self.tr.events()[seen_events:]
        if len(new) > 3:  # parallel: summarize
            self.log(f"{PAD}EVENT {dict(Counter(e['type'] for e in new))}")
        else:
            for e in new:
                extra = {k: v for k, v in e.items() if k not in ("ts", "type") and v is not None}
                self.log(f"{PAD}EVENT {e['type']} {extra}")
        state = self.tr.state(msisdn) if msisdn else None
        if state:
            self.log(f"{PAD}STATE {state}")
        return passed


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)  # Cyrillic + live progress
    parser = argparse.ArgumentParser(description="Replay jury scenarios with a step log.")
    parser.add_argument("ids", nargs="*", help="scenario ids, e.g. O12 O16; default: all")
    parser.add_argument("--live", action="store_true", help="real uvicorn, real HTTP, real seconds")
    parser.add_argument("--file", type=Path, default=SCENARIOS, help="scenario file in the jury format")
    args = parser.parse_args()

    scenarios = [s for s in load(args.file) if not args.ids or s["id"] in args.ids]
    if not scenarios:
        print(f"no scenarios match {args.ids}")
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        outbox, security_log = Path(tmp) / "sms.jsonl", Path(tmp) / "security.log"
        if args.live:
            transport: InProcess | Live = Live(outbox, security_log)
            print(f"live mode: real seconds, about {sum(_duration(s) for s in scenarios):.0f}s of waiting")
        else:
            clock = Clock()
            otp.now = clock
            config.SECURITY_LOG = security_log
            os.environ["OTP_OUTBOX"] = str(outbox)
            transport = InProcess(clock)
        runner = Runner(transport, outbox)
        results = {s["id"]: runner.run(s) for s in scenarios}
    passed = sum(results.values())
    print(f"\n{passed}/{len(results)} passed: " + ", ".join(f"{k} {'PASS' if v else 'FAIL'}" for k, v in results.items()))
    return 0 if passed == len(results) else 1


def _duration(scenario: dict) -> float:
    return sum(s["seconds"] for s in scenario["steps"] if s["op"] == "advance")


if __name__ == "__main__":
    sys.exit(main())
