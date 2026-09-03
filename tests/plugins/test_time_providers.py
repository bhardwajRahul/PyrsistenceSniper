"""Tests for the TimeProviders declarative plugin (T1547.003)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.time_providers import TimeProviders

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    """A DllName under a time provider subkey is loaded by W32Time, hence SYSTEM."""
    child = make_node(name="EvilTP", values={"DllName": r"C:\evil_time.dll"})
    tree = make_node(children={"EvilTP": child})
    plugin = make_plugin(TimeProviders, tmp_path)
    setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")
    findings = plugin.run()
    assert len(findings) == 1
    assert "evil_time.dll" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "T1547.003" in findings[0].mitre_id
