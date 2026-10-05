"""Open-then-verify path layer: the OS decides, strings only find.

Security model (agreed design):
  strings are used *only* to locate a file -- join, poison rejection, cwd.
  Every security decision (containment, type, deny) is made against the path
  OF THE OPEN HANDLE, obtained from the kernel after open():
    1. poison checks   NUL / drive-relative  -> invalid_input (schema-level)
    2. locate          absolute | join(cwd, path); cwd missing -> cwd_not_set
    3. open            the kernel resolves ., .., symlinks, junctions
    4. handle verify   real path of the fd -> containment -> type -> deny
  All IO afterwards goes through that same fd -- never a second open by path.

cwd is a per-request field (never process state: the server is concurrent);
it is validated but not trusted, because the final opened file is what gets
checked. Directory listings and ripgrep walk a verified *real path*, which
leaves a documented micro-race for them only (see README); file content reads
and writes have no window at all.
"""

from __future__ import annotations

import logging
import os
import stat as statmod
from dataclasses import dataclass

from agentfiles_shared.errors import ToolError, cwd_not_set, path_escape
from agentfiles_shared.wildcard import match as wildcard_match

from . import handlepath

log = logging.getLogger("agentfiles")

# path_escape reasons: server-side log vocabulary, never shown to the model
# (the tools collapse path_escape into their generic Unable-to message).
REASON_OUTSIDE_WORKSPACE = "outside_workspace"
REASON_HANDLE_PATH_UNAVAILABLE = "handle_path_unavailable"


def slash(path: str) -> str:
    """Normalize separators to ``/`` (V2 keeps resources posix-style on Windows)."""
    return path.replace("\\", "/")


def contains(parent: str, child: str) -> bool:
    """True when ``child`` is lexically inside ``parent``.

    Comparison is normcase'd on Windows: GetFinalPathNameByHandleW reports the
    on-disk case, which may differ from how AF_WORKSPACE was typed.
    """
    if os.name == "nt":
        parent = os.path.normcase(parent)
        child = os.path.normcase(child)
    try:
        rel = os.path.relpath(child, parent)
    except ValueError:
        # relpath raises across drives; another drive can never be inside
        return False
    return rel == "." or (not os.path.isabs(rel) and not rel.startswith(".."))


def in_whitelist(path: str, whitelist: list[str]) -> bool:
    return any(contains(directory, path) for directory in whitelist)


@dataclass
class Opened:
    """A handle that passed containment + type + deny verification."""

    fd: int
    real: str           # kernel-resolved path of THIS handle
    resource: str       # workspace-relative (posix) or absolute for whitelist
    stat: os.stat_result
    external: bool

    @property
    def is_dir(self) -> bool:
        return statmod.S_ISDIR(self.stat.st_mode)

    @property
    def is_file(self) -> bool:
        return statmod.S_ISREG(self.stat.st_mode)

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            finally:
                self.fd = -1

    def __enter__(self) -> "Opened":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def display_path(text: str) -> str:
    """Text on its way back to the model, with undecodable bytes made
    printable.

    Names taken off the filesystem carry bytes that are not valid UTF-8 as
    lone surrogates, and no JSON response can encode those: rendering fails
    after the route has already returned, so the caller sees a bare 500
    instead of an envelope. Those bytes become U+FFFD -- the same spelling
    rg's byte output already yields for the same names.
    """
    if text.isascii():
        return text
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


class Resolver:
    def __init__(self, root: str, whitelist: list[str] | None = None) -> None:
        self.root = self._handle_real(root) or os.path.realpath(root)
        self.whitelist = [
            self._handle_real(p) or os.path.realpath(p) for p in (whitelist or [])
        ]

    @staticmethod
    def _handle_real(path: str) -> str | None:
        """Kernel-resolved real path of a directory, or None if unopenable."""
        try:
            fd = handlepath.open_dir(path)
        except OSError:
            return None
        try:
            return handlepath.real_path_of_fd(fd)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    # --- locate (stage 1-2: strings only locate, they never authorize) -----

    def locate(self, path: str, cwd: str | None) -> str:
        """Full path to attempt opening. Raises cwd_not_set for a relative
        path with no working directory; makes no containment claim."""
        if os.path.isabs(path):
            return os.path.normpath(path)
        if not cwd:
            raise cwd_not_set()
        if not os.path.isabs(cwd):
            # only what this server minted via POST /v1/cwd is ever absolute;
            # a hand-crafted relative cwd has no defined base
            from agentfiles_shared.errors import invalid_input

            raise invalid_input("cwd must be an absolute path")
        return os.path.normpath(os.path.join(cwd, path))

    # --- resource naming -----------------------------------------------------

    def resource_for(self, real: str) -> str | None:
        """Workspace-relative posix resource, absolute when whitelisted,
        None when outside every containment root."""
        if contains(self.root, real):
            rel = os.path.relpath(real, self.root)
            return "." if rel == "." else slash(rel)
        if in_whitelist(real, self.whitelist):
            return slash(real)
        return None

    def resolve_child(self, base: str, relative: str) -> tuple[str, str] | None:
        """Resolve a name reported under an already-verified directory.

        Search hits come back as strings, so they get realpath + containment
        rather than a handle. ``None`` means outside every root: callers drop
        the hit, so a search cannot map what a read of it would refuse.
        """
        real = os.path.realpath(os.path.join(base, relative))
        resource = self.resource_for(real)
        return None if resource is None else (resource, real)

    # --- stage 3-4: open, then verify THE HANDLE -----------------------------

    def open_checked(
        self,
        full: str,
        *,
        flags: int,
        expect: str,          # "file" | "dir" | "any"
        deny: list[str] = (),
        on_deny=None,
        on_type=None,
    ) -> Opened:
        """Open ``full`` and authorize the result against the handle's real path.

        FileNotFoundError / IsADirectoryError / PermissionError propagate as
        OSError for the caller to map to its own tool message; containment,
        type and deny failures raise ToolError (path_escape is collapsed by
        the tools -- only logged here).

        Patterns without the error to raise would fall through as
        ``raise None``; an empty deny list with an error left over is fine
        (that is what a server with no AF_*_DENY configured passes).
        """
        if deny and on_deny is None:
            raise ValueError("deny patterns need an on_deny error to raise")

        fd = handlepath.open_path(full, flags)
        try:
            real = handlepath.real_path_of_fd(fd)
            if not real:
                # cannot determine what we opened -> fail closed
                raise path_escape(full, REASON_HANDLE_PATH_UNAVAILABLE)

            resource = self.resource_for(real)
            if resource is None:
                log.warning(
                    "containment rejected: %s resolved outside workspace (%s)",
                    full, real,
                )
                raise path_escape(full, REASON_OUTSIDE_WORKSPACE)

            st = os.fstat(fd)
            if expect == "file" and not statmod.S_ISREG(st.st_mode):
                raise (on_type or _default_type_error)(resource, "a file")
            if expect == "dir" and not statmod.S_ISDIR(st.st_mode):
                raise (on_type or _default_type_error)(resource, "a directory")
            if expect == "any" and not (
                statmod.S_ISREG(st.st_mode) or statmod.S_ISDIR(st.st_mode)
            ):
                # FIFOs, sockets, devices: only regular files and directories
                # are ever served (opens must not hang or touch a device)
                raise (on_type or _default_type_error)(resource, "a file or directory")

            if deny:
                # deny matches BOTH the real resource (a symlink named good.txt
                # pointing at .env) and the lexical one (a .env symlinked to
                # notes.txt), so neither spelling escapes the policy
                lexical = self.resource_for(os.path.normpath(full))
                if any(
                    wildcard_match(pattern, resource)
                    or (lexical is not None and wildcard_match(pattern, lexical))
                    for pattern in deny
                ):
                    raise on_deny

            return Opened(
                fd=fd, real=real, resource=resource, stat=st,
                external=not contains(self.root, real),
            )
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    # --- create (side effects only after the parent is verified) -------------

    def create_file(
        self,
        full: str,
        *,
        deny: list[str] = (),
        on_deny=None,
    ) -> Opened:
        """O_EXCL-create ``full`` under a verified parent.

        The nearest existing ancestor is opened and verified first; deny is
        matched against the *target* resource before makedirs runs, so a
        denied name produces no side effect at all. The created handle is
        re-verified (defense against an intermediate dir swapped mid-creation).
        """
        if deny and on_deny is None:
            raise ValueError("deny patterns need an on_deny error to raise")

        parent = os.path.dirname(full) or "."
        name = os.path.basename(full)
        anchor = parent
        while not os.path.exists(anchor):
            next_anchor = os.path.dirname(anchor)
            if next_anchor == anchor:
                break
            anchor = next_anchor

        if not os.path.isdir(anchor):
            raise NotADirectoryError(anchor)

        # verify the anchor directory through ITS handle
        base = self.open_checked(anchor, flags=handlepath.OPEN_RDONLY, expect="dir")
        with base:
            remainder = os.path.relpath(parent, anchor)
            real_parent = (
                base.real if remainder in (".", "") else
                os.path.normpath(os.path.join(base.real, remainder))
            )
            target_real = os.path.normpath(os.path.join(real_parent, name))

            resource = self.resource_for(target_real)
            if resource is None:
                log.warning(
                    "containment rejected: create target %s resolves outside workspace (%s)",
                    full, target_real,
                )
                raise path_escape(full, REASON_OUTSIDE_WORKSPACE)
            if deny:
                lexical = self.resource_for(os.path.normpath(full))
                if any(
                    wildcard_match(pattern, resource)
                    or (lexical is not None and wildcard_match(pattern, lexical))
                    for pattern in deny
                ):
                    raise on_deny

            # only now: side effects. Everything below is under the verified
            # anchor + a name containing no separators.
            if real_parent != base.real:
                os.makedirs(real_parent, exist_ok=True)
            fd = os.open(
                target_real,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | handlepath.O_BINARY,
                0o664,
            )
            try:
                real = handlepath.real_path_of_fd(fd)
                if real is None or self.resource_for(real) is None:
                    # an intermediate component was swapped mid-creation
                    log.warning(
                        "containment rejected: created file %s is outside workspace (%s)",
                        target_real, real,
                    )
                    raise path_escape(full, REASON_OUTSIDE_WORKSPACE)
                st = os.fstat(fd)
                if not statmod.S_ISREG(st.st_mode):
                    from agentfiles_shared.errors import path_kind

                    raise path_kind(resource, "a file")
                return Opened(
                    fd=fd, real=real, resource=resource, stat=st,
                    external=not contains(self.root, real),
                )
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise


def _default_type_error(resource: str, expected: str) -> ToolError:
    from agentfiles_shared.errors import path_kind

    return path_kind(resource, expected)


__all__ = [
    "Opened", "Resolver", "contains", "display_path", "in_whitelist", "slash",
]
