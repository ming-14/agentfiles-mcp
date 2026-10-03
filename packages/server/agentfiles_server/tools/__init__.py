"""Tool implementations.

Each module exposes ``execute(resolver, params) -> tuple[dict, str]`` where
``params`` is the already-validated input model from ``agentfiles_shared.schema``
(the route validates it, so a tool never sees an untrusted dict).
"""
