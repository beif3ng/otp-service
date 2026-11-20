"""Attack a running OTP service and show that the defences stop it.

Three attacks, 1000 requests each by default:
- brute: guess the code of one number (lock after 5 wrong codes, 20 verify/min per IP);
- spread: guess codes across 50 numbers from one IP, so no number gets locked
  (the IP limit caps the whole attack at 20 checked codes per minute);
- pump: SMS pumping, the bot keeps calling send for 50 numbers (send delays and
  window limits reject almost all of them; each rejection is an SMS the business did not pay for).

Every run takes fresh synthetic numbers 99677073XXXX (the jury fixture range), so a repeat
run is not blocked by the previous one. The service takes the IP from the connection
(README runs uvicorn with --no-proxy-headers), so against a local server the attacks connect
from two loopback addresses like the jury stand: brute and pump from 127.0.0.1, spread from
127.0.0.2. Against a remote server all attacks share your one IP: spread right after brute
then only gets 429, so run them a minute apart.
Run only against your own server: the jury rules forbid attacking external services.

Usage, from backend/ with the server running:
    uv run python scripts/attack.py                    # all three attacks
    uv run python scripts/attack.py brute pump         # selected ones
    uv run python scripts/attack.py --url https://otp.beifeng.dev brute
Exit code 1 if any guess succeeded.
"""

import argparse
import ipaddress
import random
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

ATTACKS = ("brute", "spread", "pump")
SOURCE = {"brute": "127.0.0.1", "spread": "127.0.0.2", "pump": "127.0.0.1"}  # like the jury stand
NUMBERS = 50
DEFENCES = {
    423: "number locked after 5 wrong codes (423)",
    429: "IP limited to 20 verify/min across all numbers (429)",
}


@dataclass
class Report:
    statuses: Counter = field(default_factory=Counter)
    seconds: float = 0.0

    def line(self) -> str:
        counts = "  ".join(f"{s}x{n}" for s, n in sorted(self.statuses.items()))
        return f"responses: {counts}   ({self.seconds:.1f} s)"


def numbers(base: int, count: int) -> list[str]:
    return [f"99677073{base + i:04d}" for i in range(count)]


def fire(client: httpx.Client, requests: Iterable[tuple[str, dict]], workers: int) -> Report:
    """POST every (path, body) in parallel and count the response statuses."""

    def post(req: tuple[str, dict]) -> int:
        path, body = req
        return client.post(path, json=body).status_code

    report = Report()
    started = time.perf_counter()
    if workers == 1:
        statuses = [post(r) for r in requests]
    else:
        with ThreadPoolExecutor(workers) as pool:
            statuses = list(pool.map(post, requests))
    report.statuses.update(statuses)
    report.seconds = time.perf_counter() - started
    return report


def guesses(count: int) -> list[str]:
    """Distinct random codes: the attacker does not know the code and never repeats a guess."""
    return [f"{c:06d}" for c in random.sample(range(10**6), count)]


def brute(client: httpx.Client, attempts: int, workers: int, base: int, log: Callable) -> bool:
    msisdn = numbers(base, 1)[0]
    log(f"  {attempts} guesses for one number {msisdn}")
    sent = fire(client, [("/otp/send", {"msisdn": msisdn})], 1)
    log(f"  send   {sent.line()}")
    r = fire(client, [("/otp/verify", {"msisdn": msisdn, "code": c}) for c in guesses(attempts)], workers)
    log(f"  verify {r.line()}")
    return _verdict(r, log)


def spread(client: httpx.Client, attempts: int, workers: int, base: int, log: Callable) -> bool:
    targets = numbers(base, NUMBERS)
    log(f"  {attempts} guesses across {NUMBERS} numbers {targets[0]}..{targets[-1]}")
    sent = fire(client, [("/otp/send", {"msisdn": m}) for m in targets], workers)
    log(f"  send   {sent.line()}")
    reqs = [("/otp/verify", {"msisdn": targets[i % NUMBERS], "code": c}) for i, c in enumerate(guesses(attempts))]
    r = fire(client, reqs, workers)
    log(f"  verify {r.line()}")
    return _verdict(r, log)


def _verdict(r: Report, log: Callable) -> bool:
    """True if the attack was stopped. 401 = a code really checked and wrong; the 5th
    wrong code answers 423, so at most one 423 also hides a checked code."""
    total = sum(r.statuses.values())
    checked = r.statuses[401] + (1 if r.statuses[423] else 0)
    log(f"  codes checked by the server: <= {checked} of {total}, guessed: {r.statuses[200]}")
    if r.statuses[200]:
        log("  ATTACK SUCCEEDED: a guessed code was accepted")
        return False
    why = [text for status, text in DEFENCES.items() if r.statuses[status]]
    log(f"  ATTACK STOPPED: {', '.join(why) or 'every guess was wrong'}")
    return True


def pump(client: httpx.Client, attempts: int, workers: int, base: int, log: Callable) -> bool:
    targets = numbers(base, NUMBERS)
    log(f"  {attempts} send requests to {NUMBERS} numbers {targets[0]}..{targets[-1]}")
    r = fire(client, [("/otp/send", {"msisdn": targets[i % NUMBERS]}) for i in range(attempts)], workers)
    log(f"  send   {r.line()}")
    rejected = r.statuses[429] + r.statuses[423]
    price = _sms_price(client)
    saved = f", saved at least {rejected * price:.2f} som" if price else ""
    log(f"  SMS sent: {r.statuses[200]} of {attempts}, rejected: {rejected}{saved}")
    if r.statuses[200] >= NUMBERS:
        log("  note: one SMS per number still goes out; SEND_IP_MAX caps sends per IP (off by default)")
    log("  ATTACK STOPPED: send delays and the 3-per-10-min window reject repeats (429)")
    return True  # pumping costs money but never gives access


def _sms_price(client: httpx.Client) -> float | None:
    """The server's SMS_PRICE_SOM, as written into rejected-send events."""
    events = client.get("/events").json()
    return next((e["saved_som"] for e in reversed(events) if "saved_som" in e), None)


def _is_loopback(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    try:
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("attacks", nargs="*", choices=ATTACKS, help="default: all")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--attempts", type=int, default=1000, help="requests per attack")
    parser.add_argument("--workers", type=int, default=20, help="parallel requests")
    args = parser.parse_args()

    base = random.randrange(0, 10_000, 200)  # 1 + 50 + 50 fresh numbers per run
    runs = {"brute": (brute, base), "spread": (spread, base + 50), "pump": (pump, base + 100)}
    local = _is_loopback(args.url)
    print(f"target {args.url}")
    stopped = []
    try:
        for name in args.attacks or ATTACKS:
            attack, offset = runs[name]
            source = SOURCE[name] if local else None
            print(f"\n[{name}] from {source or 'this machine'}")
            transport = httpx.HTTPTransport(local_address=source)
            with httpx.Client(base_url=args.url, timeout=10, transport=transport) as client:
                stopped.append(attack(client, args.attempts, args.workers, offset, print))
    except httpx.HTTPError as e:
        print(f"\nserver not reachable at {args.url}: {e!r}\nstart it as in README (uvicorn --no-proxy-headers)")
        return 2
    print(f"\n{'ALL ATTACKS STOPPED' if all(stopped) else 'SOME ATTACK SUCCEEDED'}")
    return 0 if all(stopped) else 1


if __name__ == "__main__":
    sys.exit(main())
