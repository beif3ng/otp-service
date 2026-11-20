FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 8000
# One worker: the lock that keeps verify atomic lives in one process.
# No proxy headers: client IP is the connection address, as in the README run.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-proxy-headers"]
