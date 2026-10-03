"""FastAPI application: /v1/* tool endpoints behind the auth middleware."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agentfiles_shared.errors import ToolError

from .config import Config
from .fslayer import Resolver
from .middleware import AuthMiddleware, parse_body
from .tools import edit, glob, grep, read, write


def create_app(config: Config) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.resolver = Resolver(config.workspace)
        app.state.config = config
        yield

    app = FastAPI(title="agentfiles-server", lifespan=lifespan)
    app.add_middleware(AuthMiddleware, tokens=config.tokens, max_skew=config.max_skew)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    def _tool(handler):
        async def route(request: Request) -> JSONResponse:
            resolver: Resolver = request.app.state.resolver
            payload = parse_body(request)
            try:
                structured, model_text = handler(resolver, payload)
            except ToolError as exc:
                return JSONResponse(
                    status_code=200,
                    content={"ok": False, "error": exc.to_payload()},
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

    app.post("/v1/read")(_tool(read.execute))
    app.post("/v1/write")(_tool(write.execute))
    app.post("/v1/edit")(_tool(edit.execute))
    app.post("/v1/glob")(_tool(glob.execute))
    app.post("/v1/grep")(_tool(grep.execute))

    return app
