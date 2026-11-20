"""Replay jury scenarios (scenarios_examples.json format) in-process and log every step.

A fake clock makes `advance 120` instant. Per step it prints the request, the response
against the expectation, the SMS from the outbox, new security events and the number state.

Usage, from backend/:
    uv run python scripts/scenarios.py            # all scenarios
    uv run python scripts/scenarios.py O12 O16    # selected ones
"""

import json
import os
import sys
import tempfile
import warnings
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))  # make `app` importable when run as a script
warnings.filterwarnings("ignore", message="Using `httpx`")  # starlette TestClient notice

from fastapi.testclient import TestClient  # noqa: E402

from app import config, otp  # noqa: E402
from app.main import app  # noqa: E402

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
    def __init__(self, clock: Clock, outbox: Path, log: Log = print) -> None:
        self.clock, self.outbox, self.log = clock, outbox, log
        self._clients: dict[str, TestClient] = {}

    def _client(self, ip: str) -> TestClient:
        if ip not in self._clients:
            self._clients[ip] = TestClient(app, client=(ip, 50000))
        return self._clients[ip]

    def _call(self, req: dict, bound: dict[str, str]):
        body = {k: _resolve(v, bound) for k, v in req.get("body", {}).items()}
        ip = req.get("client_ip", SEND_IP)
        r = self._client(ip).request(req["method"], req["path"], json=body)
        return body, ip, r

    def _deliveries(self) -> list[dict]:
        if not self.outbox.exists():
            return []
        return [json.loads(line) for line in self.outbox.read_text("utf-8").splitlines()]

    def _state(self, msisdn: object) -> str:
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

    def run(self, scenario: dict) -> bool:
        otp.reset()
        self.clock.t = START
        self.outbox.unlink(missing_ok=True)
        bound: dict[str, str] = {}
        ok = True
        self.log(f"\n=== {scenario['id']}  {scenario['title']}")
        if scenario.get("overrides"):
            self.log(f"{PAD}! overrides ignored: {scenario['overrides']}")

        for step in scenario["steps"]:
            seen_sms, seen_events = len(self._deliveries()), len(otp._events)
            prefix = f"[+{self.clock.t - START:8.3f}s]"
            op = step["op"]
            msisdn = None

            if op == "request":
                body, ip, r = self._call(step, bound)
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
                    self.log(f"{prefix} capture_delivery {msisdn}: ${step['bind']} = {mine[-1]['code']}")
                else:
                    self.log(f"{prefix} capture_delivery {msisdn}: no SMS  FAIL")
            elif op == "advance":
                self.clock.t += step["seconds"]
                passed = True
                self.log(f"{prefix} advance {step['seconds']}s -> +{self.clock.t - START:.3f}s")
            elif op == "parallel":
                reqs = step["requests"]
                with ThreadPoolExecutor(len(reqs)) as pool:
                    results = list(pool.map(lambda req: self._call(req, bound), reqs))
                msisdn = results[0][0].get("msisdn")
                got = Counter(str(r.status_code) for _, _, r in results)
                exp = step["expected"]
                passed = len(results) == exp.get("count", len(results)) and got == Counter(exp["status_counts"])
                first = reqs[0]
                self.log(f"{prefix} parallel x{len(reqs)}: {first['method']} {first['path']} "
                         f"{json.dumps(results[0][0])} ip={results[0][1]}")
                self.log(f"{PAD}-> {dict(sorted(got.items()))}   expected {exp['status_counts']}  "
                         f"{'OK' if passed else 'FAIL'}")
            else:
                raise ValueError(f"unknown op: {op}")

            ok &= passed
            for d in self._deliveries()[seen_sms:]:
                self.log(f"{PAD}SMS   {d['msisdn']}: {d['code']}  (ts {d['ts']})")
            new = list(otp._events)[seen_events:]
            if len(new) > 3:  # parallel: summarize
                self.log(f"{PAD}EVENT {dict(Counter(e['type'] for e in new))}")
            else:
                for e in new:
                    extra = {k: v for k, v in e.items() if k not in ("ts", "type") and v is not None}
                    self.log(f"{PAD}EVENT {e['type']} {extra}")
            if msisdn:
                self.log(f"{PAD}STATE {self._state(msisdn)}")

        self.log(f"=== {scenario['id']}: {'PASS' if ok else 'FAIL'}")
        return ok


def main(ids: list[str]) -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # Cyrillic titles in any Windows console
    scenarios = [s for s in load() if not ids or s["id"] in ids]
    if not scenarios:
        print(f"no scenarios match {ids}")
        return 2
    clock = Clock()
    otp.now = clock
    with tempfile.TemporaryDirectory() as tmp:
        config.SECURITY_LOG = Path(tmp) / "security.log"
        runner = Runner(clock, Path(tmp) / "sms.jsonl")
        os.environ["OTP_OUTBOX"] = str(runner.outbox)
        results = {s["id"]: runner.run(s) for s in scenarios}
    passed = sum(results.values())
    print(f"\n{passed}/{len(results)} passed: " + ", ".join(f"{k} {'PASS' if v else 'FAIL'}" for k, v in results.items()))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
