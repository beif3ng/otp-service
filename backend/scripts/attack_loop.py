"""Random attacks in a loop until Ctrl+C: keeps the dashboard live during the demo.

Every round picks brute, spread or pump from attack.py at random, with a random number
of requests and fresh synthetic numbers, then pauses a few seconds. Source addresses are
the same as in attack.py. Run only against your own server.

Usage, from backend/ with the server running:
    uv run python scripts/attack_loop.py
    uv run python scripts/attack_loop.py --url https://otp.beifeng.dev --pause 5 15
Ctrl+C prints the totals. Exit code 1 if any guess succeeded.
"""

import argparse
import random
import sys
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent))  # run as a script or imported from tests
import attack


def loop(
    client_for: Callable[[str | None], httpx.Client],
    size: tuple[int, int],
    workers: int,
    pause: tuple[float, float],
    log: Callable,
    rounds: int | None = None,
) -> tuple[Counter, int]:
    """Run random attacks until Ctrl+C (or `rounds`); return rounds per attack and successful guesses."""
    played: Counter = Counter()
    succeeded = 0
    try:
        while rounds is None or played.total() < rounds:
            name = random.choice(attack.ATTACKS)
            requests = random.randint(*size)
            base = random.randrange(0, 10_000 - attack.NUMBERS)
            client = client_for(attack.SOURCE[name])
            log(f"\n#{played.total() + 1} [{name}] {requests} requests")
            if not getattr(attack, name)(client, requests, workers, base, log):
                succeeded += 1
            played[name] += 1
            time.sleep(random.uniform(*pause))
    except KeyboardInterrupt:
        pass
    return played, succeeded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--size", type=int, nargs=2, default=(60, 300), metavar=("MIN", "MAX"), help="requests per round")
    parser.add_argument("--pause", type=float, nargs=2, default=(2, 8), metavar=("MIN", "MAX"), help="seconds between rounds")
    parser.add_argument("--workers", type=int, default=10, help="parallel requests")
    args = parser.parse_args()

    local = attack._is_loopback(args.url)
    clients: dict[str | None, httpx.Client] = {}

    def client_for(source: str | None) -> httpx.Client:
        source = source if local else None  # a remote server sees one IP anyway
        if source not in clients:
            transport = httpx.HTTPTransport(local_address=source)
            clients[source] = httpx.Client(base_url=args.url, timeout=10, transport=transport)
        return clients[source]

    print(f"target {args.url}, Ctrl+C to stop")
    try:
        played, succeeded = loop(client_for, args.size, args.workers, args.pause, print)
    except httpx.HTTPError as e:
        print(f"\nserver not reachable at {args.url}: {e!r}\nstart it as in README (uvicorn --no-proxy-headers)")
        return 2
    finally:
        for client in clients.values():
            client.close()
    rounds = ", ".join(f"{name} {n}" for name, n in sorted(played.items())) or "none"
    print(f"\nstopped after {played.total()} rounds ({rounds}); {'GUESSED CODES: ' + str(succeeded) if succeeded else 'all attacks stopped'}")
    return 1 if succeeded else 0


if __name__ == "__main__":
    sys.exit(main())
