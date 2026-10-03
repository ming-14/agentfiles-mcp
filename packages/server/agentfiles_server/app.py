"""FastAPI application: /v1/* tool endpoints behind the auth middleware."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from agentfiles_shared.errors import ToolError, invalid_input
from agentfiles_shared.schema import (
    EditInput,
    GlobInput,
    GrepInput,
    ReadInput,
    WriteInput,
)

from .config import Config
from .fslayer import Resolver
from .middleware import AuthMiddleware, parse_body
from .tools import edit, glob, grep, read, write

MAX_ERROR_DETAILS = 5

InputModel = TypeVar("InputModel", bound=BaseModel)


def _validation_detail(exc: ValidationError) -> str:
    """Short, model-visible summary of the offending fields."""
    errors = exc.errors()
    parts = []
    for error in errors[:MAX_ERROR_DETAILS]:
        location = ".".join(str(part) for part in error["loc"]) or "body"
        parts.append(f"{location}: {error['msg']}")
    if len(errors) > MAX_ERROR_DETAILS:
        parts.append(f"(+{len(errors) - MAX_ERROR_DETAILS} more)")
    return "; ".join(parts)


def create_app(config: Config) -> FastAPI:
    # Routes capture the resolver directly instead of reading it back off
    # app.state, so nothing depends on the ASGI lifespan having run.
    resolver = Resolver(config.workspace)
    app = FastAPI(title="agentfiles-server")
    app.add_middleware(AuthMiddleware, tokens=config.tokens, max_skew=config.max_skew)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    def _tool(
        model: type[InputModel],
        handler: Callable[[Resolver, InputModel], tuple[dict, str]],
    ):
        async def route(request: Request) -> JSONResponse:
            try:
                params = model.model_validate(parse_body(request))
                structured, model_text = handler(resolver, params)
            except ToolError as exc:
                return JSONResponse(
                    status_code=200,
                    content={"ok": False, "error": exc.to_payload()},
                )
            except ValidationError as exc:
                return JSONResponse(
                    status_code=200,
                    content={
                        "ok": False,
                        "error": invalid_input(_validation_detail(exc)).to_payload(),
                    },
                )
            except Exception as exc:  # noqa: BLE001 - never leak internals to the model
                return JSONResponse(
                    status_code=200,
                    content={
                        "ok": False,
                        "error": {"code": "internal", "message": f"Internal error: {exc.__class__.__name__}"},
                    },
                )
            return JSONResponse(
                content={
                    "ok": True,
                    "result": structured,
                    "modelText": model_text,
                }
            )

        return route

    app.post("/v1/read")(_tool(ReadInput, read.execute))
    app.post("/v1/write")(_tool(WriteInput, write.execute))
    app.post("/v1/edit")(_tool(EditInput, edit.execute))
    app.post("/v1/glob")(_tool(GlobInput, glob.execute))
    app.post("/v1/grep")(_tool(GrepInput, grep.execute))

    return app
