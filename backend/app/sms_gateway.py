"""Demo SMS gateway: delivers codes from the outbox to Telegram.

A separate process, like an operator's SMSC: the OTP service only appends to
outbox/sms.jsonl and never reads it; this gateway tails the file and sends each
new code to the Telegram chat bound to the number. Unbound numbers get nothing
here (the code stays in the outbox only), so jury scenarios do not change.

A number is bound by sharing one's own contact with the bot: Telegram supplies
the phone number, and a contact of someone else is refused, otherwise anyone
could bind a victim's number and receive their codes.

Run: python -m app.sms_gateway  (env TELEGRAM_BOT_TOKEN, OTP_OUTBOX, GATEWAY_DB)
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from app import config

MSISDN_RE = re.compile(r"996[0-9]{9}")  # same format as the service; no app.otp import: it opens storage

API = "https://api.telegram.org/bot{token}/{method}"
SHARE_BUTTON = {
    "keyboard": [[{"text": "Поделиться номером", "request_contact": True}]],
    "resize_keyboard": True,
    "one_time_keyboard": True,
}


class Bot:
    def __init__(self, token: str) -> None:
        self._token = token

    def call(self, method: str, http_timeout: float = 10, **params) -> dict | list | None:
        req = urllib.request.Request(
            API.format(token=self._token, method=method),
            json.dumps(params).encode(),
            {"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=http_timeout) as resp:
                return json.load(resp).get("result")
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            # The error text never contains the token: it is only in the URL path.
            print(f"telegram {method} failed: {type(e).__name__}", flush=True)
            return None

    def say(self, chat_id: int, text: str, **params) -> None:
        self.call("sendMessage", chat_id=chat_id, text=text, parse_mode="HTML", **params)


class Bindings:
    """msisdn -> chat_id, kept in a JSON file so a restart does not unbind anyone."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._map: dict[str, int] = json.loads(path.read_text("utf-8")) if path.exists() else {}

    def get(self, msisdn: str) -> int | None:
        with self._lock:
            return self._map.get(msisdn)

    def set(self, msisdn: str, chat_id: int | None) -> None:
        with self._lock:
            if chat_id is None:
                self._map.pop(msisdn, None)
            else:
                self._map[msisdn] = chat_id
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._map), "utf-8")

    def numbers_of(self, chat_id: int) -> list[str]:
        with self._lock:
            return [m for m, c in self._map.items() if c == chat_id]


def normalize(phone: str) -> str | None:
    """Telegram gives '+996...' or '996...'; returns a valid msisdn or None."""
    digits = "".join(ch for ch in phone if ch.isdigit())
    return digits if MSISDN_RE.fullmatch(digits) else None


def masked(msisdn: str) -> str:
    return msisdn[:6] + "***" + msisdn[-2:]


def handle(bot: Bot, bindings: Bindings, message: dict) -> None:
    chat_id = message["chat"]["id"]
    contact = message.get("contact")
    text = message.get("text", "")
    if contact:
        if contact.get("user_id") != message.get("from", {}).get("id"):
            bot.say(chat_id, "Можно привязать только свой номер: нажмите кнопку ниже.", reply_markup=SHARE_BUTTON)
            return
        msisdn = normalize(contact.get("phone_number", ""))
        if msisdn is None:
            bot.say(chat_id, "Демо принимает только номера Кыргызстана: 996XXXXXXXXX.")
            return
        bindings.set(msisdn, chat_id)
        bot.say(
            chat_id,
            f"Номер +{msisdn} привязан. Коды входа будут приходить сюда.\nОтвязать: /stop",
            reply_markup={"remove_keyboard": True},
        )
    elif text.startswith("/stop"):
        for msisdn in bindings.numbers_of(chat_id):
            bindings.set(msisdn, None)
        bot.say(chat_id, "Номер отвязан. Коды сюда больше не придут.")
    else:
        bot.say(
            chat_id,
            "Это демо-шлюз OTP-сервиса: вместо SMS код входа приходит сюда.\n"
            "Поделитесь своим номером, затем войдите на https://otp.beifeng.dev/demo",
            reply_markup=SHARE_BUTTON,
        )


def poll_updates(bot: Bot, bindings: Bindings) -> None:
    offset = 0
    while True:
        updates = bot.call("getUpdates", http_timeout=40, offset=offset, timeout=30)
        if updates is None:
            time.sleep(3)
            continue
        for update in updates:
            offset = update["update_id"] + 1
            if "message" in update:
                try:
                    handle(bot, bindings, update["message"])
                except Exception as e:  # noqa: BLE001 — one odd update must not stop the bot for everyone
                    print(f"telegram update skipped: {type(e).__name__}", flush=True)


def deliver(bot: Bot, bindings: Bindings, line: str) -> None:
    try:
        sms = json.loads(line)
        msisdn, code = sms["msisdn"], sms["code"]
    except (ValueError, KeyError, TypeError):
        return
    chat_id = bindings.get(msisdn)
    if chat_id is None:
        return
    bot.say(
        chat_id,
        f"Код входа: <code>{code}</code>\nДействует {config.OTP_TTL / 60:g} мин. Никому его не сообщайте.",
        protect_content=True,
    )
    print(f"delivered to telegram: {masked(msisdn)}", flush=True)  # never the code


def tail_outbox(bot: Bot, bindings: Bindings, path: Path) -> None:
    """Send only lines written after start: old codes are not re-delivered."""
    pos = path.stat().st_size if path.exists() else 0
    while True:
        time.sleep(0.3)
        if not path.exists():
            pos = 0
            continue
        size = path.stat().st_size
        if size < pos:  # file was recreated
            pos = 0
        if size == pos:
            continue
        with path.open("rb") as f:
            f.seek(pos)
            chunk = f.read()
        complete = chunk[: chunk.rfind(b"\n") + 1]  # skip a line still being written
        pos += len(complete)
        for line in complete.decode("utf-8", errors="replace").splitlines():
            deliver(bot, bindings, line)


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("TELEGRAM_BOT_TOKEN is not set: gateway is off", flush=True)
        return
    bot = Bot(token)
    bindings = Bindings(Path(os.environ.get("GATEWAY_DB") or config.REPO_ROOT / "gateway.json"))
    outbox = config.outbox_path()
    threading.Thread(target=poll_updates, args=(bot, bindings), daemon=True).start()
    print(f"gateway: watching {outbox}", flush=True)
    tail_outbox(bot, bindings, outbox)


if __name__ == "__main__":
    main()
