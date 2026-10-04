"""FastAPI application: /v1/* tool endpoints behind the auth middleware."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TypeVar

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from agentfiles_shared.errors import ToolError, invalid_cwd, invalid_input
from agentfiles_shared.schema import (
    EditInput,
    GlobInput,
    GrepInput,
    ReadInput,
    WriteInput,
    check_path_value,
)

from .config import Config
from .fslayer import Resolver
from .handlepath import OPEN_RDONLY
from .middleware import AuthMiddleware, parse_body
from .tools import edit, glob, grep, read, write
from .transport import download

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
    resolver = Resolver(config.workspace, config.external_whitelist)
    app = FastAPI(title="agentfiles-server")
    app.add_middleware(
        AuthMiddleware,
        tokens=config.tokens,
        max_skew=config.max_skew,
        max_body=config.max_body_bytes,
    )

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True}

    def _tool(
        model: type[InputModel],
        handler: Callable[[Resolver, Config, InputModel], tuple[dict, str]],
    ):
        async def route(request: Request) -> JSONResponse:
            try:
                params = model.model_validate(parse_body(request))
                # Handlers are sync (file IO today, ripgrep subprocesses in
                # step 5); run them off the event loop so they can't stall
                # every other request.
                structured, model_text = await run_in_threadpool(
                    handler, resolver, config, params
                )
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

    @app.get("/v1/transport/download")
    async def transport_download(path: str) -> Response:
        # Signature (including the signed query) was verified by the middleware;
        # FileResponse preparation is sync file IO, so keep it off the loop.
        return await run_in_threadpool(download, resolver, config, path)

    @app.post("/v1/cwd")
    async def set_cwd(request: Request) -> JSONResponse:
        """Validate a working directory through a handle and return its
        kernel-resolved path. Relative input resolves against the workspace
        root (the client has no cwd yet -- that is what it is setting).
        One error covers missing / not-a-directory / outside containment, so
        set_cwd cannot be used to map the server's filesystem either."""
        try:
            body = parse_body(request)
            path = body.get("path")
            if not isinstance(path, str) or not path:
                raise invalid_input("path must be a non-empty string")
            check_path_value(path)
            full = path if os.path.isabs(path) else os.path.join(resolver.root, path)
            opened = resolver.open_checked(
                os.path.normpath(full), flags=OPEN_RDONLY, expect="dir"
            )
            opened.close()
        except ToolError as exc:
            if exc.code == "invalid_input":
                return JSONResponse(
                    status_code=200, content={"ok": False, "error": exc.to_payload()}
                )
            return JSONResponse(
                status_code=200,
                content={"ok": False, "error": invalid_cwd(str(path)).to_payload()},
            )
        except ValueError as exc:
            # check_path_value (NUL / drive-relative)
            return JSONResponse(
                status_code=200,
                content={"ok": False, "error": invalid_input(str(exc)).to_payload()},
            )
        except OSError:
            return JSONResponse(
                status_code=200,
                content={"ok": False, "error": invalid_cwd(str(path)).to_payload()},
            )
        return JSONResponse(content={"ok": True, "cwd": opened.real})

    return app
