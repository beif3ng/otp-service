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
