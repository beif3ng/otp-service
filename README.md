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

Ключ номера в Redis живёт `max(SEND_WINDOW, OTP_TTL, LOCK_SECONDS)` = 900 с от последнего обращения: номер без активности 15 минут забывается целиком (счётчик ошибок, истёкший код → 401 вместо 410).
