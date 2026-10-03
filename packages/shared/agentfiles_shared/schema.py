"""Pydantic schemas mirroring the V2 (packages/core) file-tool contracts.

Input fields and output shapes are kept field-for-field identical to
packages/core/src/tool/{read,write,edit,glob,grep}.ts so the local MCP proxy
can expose the same JSON schema the model is trained against.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

# --- constants (packages/core/src/tool/read-filesystem.ts) ----------------

MAX_READ_LINES = 2_000
MAX_READ_BYTES = 50 * 1024
MAX_LINE_LENGTH = 2_000
MAX_LINE_SUFFIX = f"... (line truncated to {MAX_LINE_LENGTH} chars)"
MAX_MEDIA_INGEST_BYTES = 20 * 1024 * 1024
DEFAULT_IMAGE_MAX_WIDTH = 2_000
DEFAULT_IMAGE_MAX_HEIGHT = 2_000
DEFAULT_IMAGE_MAX_BASE64_BYTES = 5 * 1024 * 1024


# --- read -----------------------------------------------------------------

class ReadInput(BaseModel):
    path: str = Field(description="Path of the file or directory to read")
    offset: Optional[int] = Field(
        default=None, ge=1,
        description="The 1-based directory entry or text line offset to start reading from",
    )
    limit: Optional[int] = Field(
        default=None, ge=1, le=MAX_READ_LINES,
        description="The maximum number of directory entries or text lines to read",
    )


class FileSystemContent(BaseModel):
    """Small-file / media result: FileSystem.Content."""

    uri: str
    name: Optional[str] = None
    content: str
    encoding: Literal["utf8", "base64"]
    mime: str


class TextPage(BaseModel):
    type: Literal["text-page"] = "text-page"
    content: str
    mime: str
    offset: int
    truncated: bool
    next: Optional[int] = None


class Entry(BaseModel):
    path: str
    type: Literal["file", "directory"]


class ListPage(BaseModel):
    entries: list[Entry]
    truncated: bool
    next: Optional[int] = None


# --- write ----------------------------------------------------------------

class WriteInput(BaseModel):
    path: str = Field(
        description="File path to write. Relative paths resolve within the active "
        "Location; external absolute paths require external_directory approval."
    )
    content: str = Field(description="Content to write to the file")


class WriteOutput(BaseModel):
    operation: Literal["write"] = "write"
    target: str
    resource: str
    existed: bool


# --- edit -----------------------------------------------------------------

class EditInput(BaseModel):
    path: str = Field(description="File path to edit")
    old_string: str = Field(alias="oldString", description="Exact text to replace")
    new_string: str = Field(alias="newString", description="Replacement text")
    replace_all: Optional[bool] = Field(
        default=None, alias="replaceAll",
        description="Replace all exact occurrences of oldString (default false)",
    )

    model_config = {"populate_by_name": True}


class FileDiffInfo(BaseModel):
    file: Optional[str] = None
    patch: Optional[str] = None
    additions: int = 0
    deletions: int = 0
    status: Optional[Literal["added", "deleted", "modified"]] = None


class EditOutput(BaseModel):
    files: list[FileDiffInfo]
    replacements: int


# --- glob / grep ----------------------------------------------------------

class GlobInput(BaseModel):
    pattern: str = Field(description="Glob pattern to match files against")
    path: Optional[str] = Field(
        default=None, description="Relative directory to search. Defaults to the active Location."
    )
    limit: Optional[int] = Field(default=None, ge=1, description="Maximum results to return")


class GrepInput(BaseModel):
    pattern: str = Field(description="Regex pattern to search for in file contents")
    path: Optional[str] = Field(
        default=None, description="Relative directory to search. Defaults to the active Location."
    )
    include: Optional[str] = Field(
        default=None,
        description='File glob to include in the search (for example, "*.js" or "*.{ts,tsx}")',
    )
    limit: Optional[int] = Field(default=None, ge=1, description="Maximum matches to return")


class Submatch(BaseModel):
    text: str
    start: int
    end: int


class Match(BaseModel):
    entry: Entry
    line: int
    offset: int
    text: str
    submatches: list[Submatch] = []


# --- transport envelope ---------------------------------------------------

class ErrorPayload(BaseModel):
    code: str
    message: str


class ToolResponse(BaseModel):
    """REST envelope: structured output + the exact text shown to the model."""

    ok: bool
    result: Optional[dict] = None
    model_text: Optional[str] = Field(default=None, alias="modelText")
    error: Optional[ErrorPayload] = None

    model_config = {"populate_by_name": True}
