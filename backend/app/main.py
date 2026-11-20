from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.routers import otp

# Paths exactly as in the spec, no /api prefix.
app = FastAPI(title="otp-service")
app.include_router(otp.router)


@app.exception_handler(RequestValidationError)
def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    """The contract wants 400 for any bad input, not FastAPI's 422."""
    return JSONResponse({"detail": "invalid request"}, 400)
