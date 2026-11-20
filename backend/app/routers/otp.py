import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app import otp

router = APIRouter()


async def json_body(request: Request) -> Any:
    """Parse the body ourselves: bad JSON must give 400 and, for verify, still
    pass the IP limit first. Returns None for a body that is not JSON."""
    try:
        return json.loads(await request.body())
    except (ValueError, UnicodeDecodeError):
        return None


def _field(body: Any, name: str) -> Any:
    return body.get(name) if isinstance(body, dict) else None


def _respond(result: otp.Result) -> JSONResponse:
    return JSONResponse({"detail": result.detail}, result.status, headers=result.headers)


def _schema(*fields: str) -> dict:
    props = {f: {"type": "string"} for f in fields}
    return {
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {"type": "object", "properties": props, "required": list(fields)}
                }
            },
        }
    }


# Endpoints are sync on purpose: threading.Lock inside async def would block the loop.
@router.post("/otp/send", openapi_extra=_schema("msisdn"))
def send(request: Request, body: Any = Depends(json_body)) -> JSONResponse:
    return _respond(otp.send(_field(body, "msisdn"), request.client.host if request.client else None))


@router.post("/otp/verify", openapi_extra=_schema("msisdn", "code"))
def verify(request: Request, body: Any = Depends(json_body)) -> JSONResponse:
    ip = request.client.host if request.client else "unknown"
    return _respond(otp.verify(_field(body, "msisdn"), _field(body, "code"), ip))


@router.get("/events")
def events() -> list[dict]:
    return otp.recent_events()
