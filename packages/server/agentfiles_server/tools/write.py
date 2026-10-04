"""write tool — open-then-verify, strict version receipt.

Flow: locate -> target lock -> open existing handle (verify: containment,
type, deny, version CAS) OR verify parent + O_EXCL create -> write through
the handle. A denied name produces no side effect: deny is matched before
makedirs runs. path_escape collapses to `Unable to write <path>` (logged
server-side) so probing cannot map the server's filesystem.
"""

from __future__ import annotations

from agentfiles_shared.errors import (
    ToolError,
    unable_to_write,
)
from agentfiles_shared.schema import WriteInput

from .. import filemut
from ..config import Config
from ..fslayer import Resolver
from ..handlepath import OPEN_RDWR

# verbatim: version policy is actionable; cwd_not_set says how to proceed;
# invalid_input points at the model's own arguments. path_escape does not
# leak existence and therefore collapses.
_TRANSPARENT_CODES = {
    "version_missing",
    "version_mismatch",
    "write_deny",
    "cwd_not_set",
    "invalid_input",
}


def execute(
    resolver: Resolver, config: Config, params: WriteInput
) -> tuple[dict, str]:
    try:
        return _run(resolver, config, params)
    except ToolError as exc:
        if exc.code in _TRANSPARENT_CODES:
            raise
        raise unable_to_write(params.path) from None
    except OSError:
        # read-only file, disk full, missing parent dir: a tool error the
        # model can act on, never an `internal` one
        raise unable_to_write(params.path) from None


def _run(
    resolver: Resolver, config: Config, params: WriteInput
) -> tuple[dict, str]:
    full = resolver.locate(params.path, params.cwd)
    data = params.content.encode("utf-8")
    expected = params.expected_version
    deny_error = ToolError("write_deny", f"Unable to write {params.path}")

    with filemut.target_lock(full):
        opened = None
        created = False
        try:
            opened = resolver.open_checked(
                full,
                flags=OPEN_RDWR,
                expect="file",
                deny=config.write_deny,
                on_deny=deny_error,
            )
        except FileNotFoundError:
            # absent: create -- but only when no receipt claims it existed
            if expected is not None:
                raise filemut.version_mismatch_write() from None
            opened = resolver.create_file(
                full, deny=config.write_deny, on_deny=deny_error
            )
            created = True
        except IsADirectoryError:
            raise unable_to_write(params.path) from None

        try:
            if created:
                handle = filemut.adopt_created(opened)  # fd ownership moves here
            else:
                # write replaces every byte: only the BOM prefix is worth reading
                handle = filemut.verify_opened(
                    opened,
                    expected,
                    on_missing=filemut.version_missing_write(),
                    on_mismatch=filemut.version_mismatch_write(),
                    read_content=False,
                )
            try:
                # exactly one BOM: old file had one, or the new content does
                had_bom = handle.had_bom or filemut.has_bom(data)
                filemut.modify(handle, filemut.join_bom(data, had_bom))
            except BaseException:
                handle.close()
                raise
            # marker from the handle we wrote through, before it closes
            version = filemut.finish(handle)
        finally:
            opened.close()

    real, resource = opened.real, opened.resource
    verb = "Wrote" if not created else "Created"
    model_text = f"{verb} file successfully: {resource}"
    result = {
        "operation": "write",
        "target": real,
        "resource": resource,
        "existed": not created,
        "version": version.model_dump(by_alias=True),
    }
    return result, model_text
