"""Tests for LOLBin name loading: bundled snapshot, cache file, and fallback."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

from pyrsistencesniper.core.lolbins import (
    _load_bundled,
    _load_cache,
    load_lolbin_names,
)


def test_load_bundled_returns_nonempty_frozenset() -> None:
    """A release detects LOLBins offline, with no fetched list behind it."""
    names = _load_bundled()
    assert isinstance(names, frozenset)
    assert len(names) > 0
    assert "mshta.exe" in names


def test_load_cache_returns_none_when_missing(tmp_path: Path) -> None:
    """A first run has no cache yet, which is the normal state and not a failure."""
    with patch(
        "pyrsistencesniper.core.lolbins._CACHE_FILE",
        tmp_path / "nonexistent.json",
    ):
        assert _load_cache() is None


def test_load_cache_returns_frozenset(tmp_path: Path) -> None:
    """A refreshed list is read back, so a new LOLBin counts before a release."""
    cache = tmp_path / "lolbins.json"
    cache.write_text(json.dumps(["mshta.exe", "certutil.exe"]))
    with patch("pyrsistencesniper.core.lolbins._CACHE_FILE", cache):
        result = _load_cache()
    assert result is not None
    assert "mshta.exe" in result
    assert "certutil.exe" in result


def test_load_cache_returns_none_on_corrupt(tmp_path: Path) -> None:
    """A truncated cache is discarded rather than raised inside the scan."""
    cache = tmp_path / "lolbins.json"
    cache.write_text("not json")
    with patch("pyrsistencesniper.core.lolbins._CACHE_FILE", cache):
        assert _load_cache() is None


def test_load_lolbin_names_prefers_cache() -> None:
    """A refreshed cache wins, so list updates take effect without a release."""
    cache_names = frozenset({"custom.exe"})
    with patch(
        "pyrsistencesniper.core.lolbins._load_cache",
        return_value=cache_names,
    ):
        result = load_lolbin_names()
    assert result is cache_names


def test_load_lolbin_names_falls_back_to_bundled() -> None:
    """A machine that never fetched the list still gets LOLBin detection."""
    with patch(
        "pyrsistencesniper.core.lolbins._load_cache",
        return_value=None,
    ):
        result = load_lolbin_names()
    assert isinstance(result, frozenset)
    assert len(result) > 0
