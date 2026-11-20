import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app import history, otp

router = APIRouter()


MAX_BODY = 4096  # a valid body is under 100 bytes; a huge one would stall the event loop


async def json_body(request: Request) -> Any:
    """Parse the body ourselves: bad JSON must give 400 and, for verify, still
    pass the IP limit first. Returns None for a body that is not JSON or is
    over MAX_BODY (read no further than that).
    RecursionError: a deeply nested body like [[[...]]] is bad input, not a 500."""
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY:
            return None
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


Body = Annotated[Any, Depends(json_body)]


def _client_ip(request: Request) -> str:
    """IP of the connection; X-Forwarded-For is ignored (uvicorn --no-proxy-headers)."""
    return request.client.host if request.client else "unknown"


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
def send(request: Request, body: Body) -> JSONResponse:
    return _respond(otp.send(_field(body, "msisdn"), _client_ip(request)))


@router.post("/otp/verify", openapi_extra=_schema("msisdn", "code"))
def verify(request: Request, body: Body) -> JSONResponse:
    return _respond(otp.verify(_field(body, "msisdn"), _field(body, "code"), _client_ip(request)))


@router.get("/events")
def events() -> list[dict]:
    return otp.recent_events()


@router.get("/stats")
def stats() -> dict:
    return otp.stats()


@router.get("/stats/history")
def stats_history() -> dict:
    return history.history()
