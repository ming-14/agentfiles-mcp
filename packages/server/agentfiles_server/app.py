"""FastAPI application: /v1/* tool endpoints behind the auth middleware."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

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
from .fslayer import Resolver, display_path
from .handlepath import OPEN_RDONLY
from .middleware import AuthMiddleware, parse_body
from .tools import edit, glob, grep, read, write
from .transport import download

MAX_ERROR_DETAILS = 5

InputModel = TypeVar("InputModel", bound=BaseModel)


def _scrub(value: Any) -> Any:
    """Walk a response body and make every string in it encodable."""
    if isinstance(value, str):
        return display_path(value)
    if isinstance(value, (list, tuple)):
        return [_scrub(item) for item in value]
    if isinstance(value, dict):
        return {key: _scrub(item) for key, item in value.items()}
    return value


def _json(content: dict, status_code: int = 200) -> JSONResponse:
    """Every response leaves through here.

    A name taken off the filesystem may carry bytes that are not valid UTF-8,
    and no JSON response can encode those: rendering fails once the route has
    already returned, so the caller gets a bare 500 instead of an envelope --
    a place the route's own try/except cannot reach.
    """
    return JSONResponse(status_code=status_code, content=_scrub(content))


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
    # a cwd is the base for relative reads *and* writes, so a directory either
    # deny list protects cannot serve as one
    cwd_deny = list(dict.fromkeys(config.read_deny + config.write_deny))
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
                return _json({"ok": False, "error": exc.to_payload()})
            except ValidationError as exc:
                return _json(
                    {
                        "ok": False,
                        "error": invalid_input(_validation_detail(exc)).to_payload(),
                    }
                )
            except Exception as exc:  # noqa: BLE001 - never leak internals to the model
                return _json(
                    {
                        "ok": False,
                        "error": {"code": "internal", "message": f"Internal error: {exc.__class__.__name__}"},
                    }
                )
            return _json(
                {
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
        Both deny lists apply: a directory either policy protects cannot be
        the base for relative paths. One error covers missing /
        not-a-directory / outside containment / denied, so set_cwd cannot be
        used to map the server's filesystem either."""
        try:
            body = parse_body(request)
            path = body.get("path")
            if not isinstance(path, str) or not path:
                raise invalid_input("path must be a non-empty string")
            check_path_value(path)
            full = resolver.locate(path, resolver.root)
            opened = resolver.open_checked(
                full, flags=OPEN_RDONLY, expect="dir",
                deny=cwd_deny, on_deny=invalid_cwd(str(path)),
            )
            opened.close()
        except ToolError as exc:
            if exc.code == "invalid_input":
                return _json({"ok": False, "error": exc.to_payload()})
            return _json(
                {"ok": False, "error": invalid_cwd(str(path)).to_payload()}
            )
        except ValueError as exc:
            # check_path_value (NUL / drive-relative)
            return _json(
                {"ok": False, "error": invalid_input(str(exc)).to_payload()}
            )
        except OSError:
            return _json(
                {"ok": False, "error": invalid_cwd(str(path)).to_payload()}
            )
        return _json({"ok": True, "cwd": opened.real})

    return app
