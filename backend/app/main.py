from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv()

# Paths exactly as in the spec, no /api prefix. Routers: app/routers/otp.py (A).
app = FastAPI(title="otp-service")
