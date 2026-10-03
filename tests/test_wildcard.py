"""Wildcard matching: V2-compatible rules."""

from __future__ import annotations

import os

from agentfiles_shared.wildcard import match


def test_star_matches_anything():
    assert match("*.env", ".env")
    assert match("*.env", "app/.env")
    assert match("*", "anything/goes")


def test_question_mark_matches_one_char():
    assert match("a?c", "abc")
    assert not match("a?c", "ac")


def test_anchored_full_match():
    assert not match("*.env", "notes.env.backup.txt")
    assert match("*.env.*", "app.env.local")


def test_ignores_separator_style():
    assert match("*", "a\\b")
    assert match("src/*", "src\\main.ts")


def test_windows_case_insensitive():
    if os.name != "nt":
        return
    assert match("*.ENV", "app.env")
    assert match("*.env", "APP.ENV")


def test_regex_metacharacters_are_literal():
    assert match("a.b", "a.b")
    assert not match("a.b", "axb")
    assert match("*+", "1++")
    assert match("a(b)", "a(b)")
