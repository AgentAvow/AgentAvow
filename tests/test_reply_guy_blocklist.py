"""The reply-guy opt-out blocklist: a handle that asks us to stop stays stopped."""
from __future__ import annotations

from src.marketing.reply_guy.monitor import _HANDLE_BLOCKLIST, _is_blocklisted


def test_blocklisted_handle_matches_case_and_at_insensitively():
    assert "xeiaso.net" in _HANDLE_BLOCKLIST
    assert _is_blocklisted("xeiaso.net")
    assert _is_blocklisted("XeIaso.net")      # case-insensitive
    assert _is_blocklisted("@xeiaso.net")     # leading @ stripped
    assert _is_blocklisted("  xeiaso.net  ")  # whitespace stripped


def test_non_blocklisted_handles_pass_through():
    assert not _is_blocklisted("someone.bsky.social")
    assert not _is_blocklisted("")
    assert not _is_blocklisted(None)  # type: ignore[arg-type]
