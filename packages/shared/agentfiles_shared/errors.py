"""Model-visible error texts.

Every string here is verbatim from the V2 implementation (packages/core/src/tool)
so that the remote server emits messages identical to what the model expects.
"""

from __future__ import annotations


class ToolError(Exception):
    """A tool failure whose message is shown verbatim to the model."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def to_payload(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


# --- read -----------------------------------------------------------------

def binary_file(resource: str) -> ToolError:
    return ToolError("binary_file", f"Cannot read binary file: {resource}")


def media_ingest_limit(resource: str, limit: int) -> ToolError:
    return ToolError(
        "media_ingest_limit", f"Media exceeds {limit} byte ingestion limit: {resource}"
    )


def malformed_utf8(resource: str) -> ToolError:
    return ToolError("malformed_utf8", f"File is not valid UTF-8: {resource}")


def offset_out_of_range(offset: int) -> ToolError:
    return ToolError("offset_out_of_range", f"Offset {offset} is out of range")


def path_kind(resource: str, expected: str) -> ToolError:
    return ToolError("path_kind", f"Path is not {expected}: {resource}")


def image_decode(resource: str) -> ToolError:
    return ToolError("image_decode", f"Image could not be decoded: {resource}")


def image_size(resource: str, width: int, height: int, base64_bytes: int,
               max_width: int, max_height: int, max_bytes: int) -> ToolError:
    return ToolError(
        "image_size",
        f"Image {resource} is {width}x{height} with base64 size {base64_bytes}, "
        f"exceeding configured limits {max_width}x{max_height}/{max_bytes} bytes",
    )


def unable_to_read(path: str) -> ToolError:
    return ToolError("unable_to_read", f"Unable to read {path}")


# --- write ----------------------------------------------------------------

def unable_to_write(path: str) -> ToolError:
    return ToolError("unable_to_write", f"Unable to write {path}")


# --- edit -----------------------------------------------------------------

def edit_identical() -> ToolError:
    return ToolError(
        "edit_identical",
        "No changes to apply: oldString and newString are identical.",
    )


def edit_empty_old() -> ToolError:
    return ToolError(
        "edit_empty_old",
        "oldString must not be empty. Use write to create or overwrite a file.",
    )


def edit_not_found() -> ToolError:
    return ToolError(
        "edit_not_found",
        "Could not find oldString in the file. It must match exactly, "
        "including whitespace and indentation.",
    )


def edit_multiple_matches() -> ToolError:
    return ToolError(
        "edit_multiple_matches",
        "Found multiple exact matches for oldString. Provide more surrounding "
        "context or set replaceAll to true.",
    )


def edit_stale_content() -> ToolError:
    return ToolError(
        "edit_stale_content",
        "File changed after permission approval. Read it again before editing.",
    )


def unable_to_edit(path: str) -> ToolError:
    return ToolError("unable_to_edit", f"Unable to edit {path}")


# --- glob / grep ----------------------------------------------------------

def unable_to_find_files(pattern: str) -> ToolError:
    return ToolError("unable_to_find", f"Unable to find files matching {pattern}")


def unable_to_grep(pattern: str) -> ToolError:
    return ToolError("unable_to_grep", f"Unable to grep for {pattern}")


# --- transport / path -----------------------------------------------------

def invalid_input(detail: str) -> ToolError:
    return ToolError("invalid_input", f"Invalid tool input: {detail}")


def path_escape(path: str, reason: str) -> ToolError:
    """reason: relative_escape | location_escape | non_directory_ancestor"""
    return ToolError("path_escape", f"Unable to resolve {path} ({reason})")


def unauthorized(detail: str = "Invalid or missing credentials") -> ToolError:
    return ToolError("unauthorized", detail)
