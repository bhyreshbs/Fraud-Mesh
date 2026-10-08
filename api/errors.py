"""PRD §4 error format: {"error": {"code", "message", "request_id"}} on every non-2xx response."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

STATUS_FOR = {
    "UNAUTHENTICATED": 401, "SIGNATURE_INVALID": 401, "STALE_TIMESTAMP": 401,
    "FORBIDDEN": 403, "NOT_FOUND": 404, "DUPLICATE_EVENT": 409, "CONFLICT": 409,
    "PAYLOAD_TOO_LARGE": 413, "VALIDATION_FAILED": 422, "RATE_LIMITED": 429, "ENGINE_UNAVAILABLE": 503,
}
_CODE_FOR_STATUS = {401: "UNAUTHENTICATED", 403: "FORBIDDEN", 404: "NOT_FOUND", 405: "NOT_FOUND", 409: "CONFLICT",
                    413: "PAYLOAD_TOO_LARGE", 422: "VALIDATION_FAILED", 429: "RATE_LIMITED", 503: "ENGINE_UNAVAILABLE"}


class ApiError(Exception):
    def __init__(self, code: str, message: str = "", status: int | None = None) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code.replace("_", " ").lower()
        self.status = status or STATUS_FOR.get(code, 400)


def request_id_of(request: Request) -> str:
    return getattr(request.state, "request_id", "req_unknown")


def error_response(request: Request, code: str, message: str, status: int) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "request_id": request_id_of(request)}}
    return JSONResponse(body, status_code=status)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(request, exc.code, exc.message, exc.status)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()))
        return error_response(request, "VALIDATION_FAILED", f"{where}: {first.get('msg', 'invalid request')}", 422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _CODE_FOR_STATUS.get(exc.status_code, "CONFLICT" if exc.status_code < 500 else "ENGINE_UNAVAILABLE")
        return error_response(request, code, str(exc.detail), exc.status_code)

    @app.exception_handler(KeyError)
    async def _key_error(request: Request, exc: KeyError) -> JSONResponse:   # engine.api raises KeyError for unknown cases
        return error_response(request, "NOT_FOUND", "case not found", 404)
