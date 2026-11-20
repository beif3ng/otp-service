from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse

from app.routers import otp
from app.store import StoreUnavailable

# Paths exactly as in the spec, no /api prefix.
app = FastAPI(title="otp-service")
app.include_router(otp.router)

STATIC = Path(__file__).parent / "static"


@app.get("/dashboard", include_in_schema=False)
def dashboard() -> FileResponse:
    """Security events page: static HTML that polls /stats and /events."""
    return FileResponse(STATIC / "dashboard.html")


@app.exception_handler(StoreUnavailable)
def store_unavailable(_: Request, exc: StoreUnavailable) -> JSONResponse:
    """Redis is down: a clear 503 instead of a 500 traceback."""
    return JSONResponse({"detail": "storage unavailable"}, 503)


@app.exception_handler(RequestValidationError)
def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    """The contract wants 400 for any bad input, not FastAPI's 422."""
    return JSONResponse({"detail": "invalid request"}, 400)
