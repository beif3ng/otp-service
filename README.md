# otp-service

REST API выдачи и проверки одноразовых кодов (ТЗ 6, INAI 2026).

## Запуск

Python 3.12+:

```
cd backend
pip install -r requirements.txt
uvicorn app.main:app --workers 1
```

Swagger — http://localhost:8000/docs

## Docker Compose + Redis (бонус)

```
docker compose up --build
```

Backend на http://localhost:8000, состояние — в Redis с TTL, коды — в `outbox/sms.jsonl` в корне репозитория. HMAC-ключ создаётся один раз в отдельном volume (не в Redis и не в git): после перезапуска backend выданные коды остаются действительными. Без `REDIS_URL` сервис хранит всё в памяти.

Номер без активности `max(SEND_WINDOW, OTP_TTL, LOCK_SECONDS)` = 900 с забывается целиком (счётчик ошибок, истёкший код → 401 вместо 410) — одинаково в памяти и в Redis. `REDIS_URL` без `OTP_SECRET` или `OTP_SECRET_FILE` не запустится: после рестарта новый ключ сделал бы верные коды неверными.
