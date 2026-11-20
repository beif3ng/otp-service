# otp-service

REST API выдачи и проверки одноразовых кодов (ТЗ 6, INAI 2026).

## Запуск

Python 3.12+:

```
cd backend
pip install -r requirements.txt
uvicorn app.main:app --workers 1 --no-proxy-headers
```

Swagger — http://localhost:8000/docs

- Коды («SMS») — в `outbox/sms.jsonl` в корне репозитория (не в `backend/`), одна JSON-строка на выдачу: `{"ts": "...", "msisdn": "996770730000", "code": "012345"}`. Актуальный код номера — последняя строка для него. Другой путь — env `OTP_OUTBOX`.
- IP клиента — адрес соединения. `X-Forwarded-For` не принимается (`--no-proxy-headers`): иначе uvicorn поверил бы ему с `127.0.0.1`, и перебор с подменой заголовка обошёл бы лимит 20 `verify` в минуту с одного IP.
- `GET /stats` — счётчики событий безопасности по типам с запуска и `saved_som` (сумма по отклонённым `send`); `GET /events` — последние 200 событий.
- Время — реальное, режима подмены часов в сервисе нет: `advance` в сценариях — обычное ожидание.

## Docker Compose + Redis (бонус)

```
docker compose up --build
```

Backend на http://localhost:8000, состояние — в Redis с TTL, коды — в `outbox/sms.jsonl` в корне репозитория. HMAC-ключ создаётся один раз в отдельном volume (не в Redis и не в git): после перезапуска backend выданные коды остаются действительными. Без `REDIS_URL` сервис хранит всё в памяти.

Номер без активности 24 ч (`max(SEND_WINDOW, OTP_TTL, LOCK_SECONDS, 86400)`) забывается целиком (счётчик ошибок и истёкший код) — одинаково в памяти и в Redis. До этого истёкший код отвечает 410. `REDIS_URL` без `OTP_SECRET` или `OTP_SECRET_FILE` не запустится: после рестарта новый ключ сделал бы верные коды неверными.
