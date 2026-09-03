"""Tests for the FontDrivers plugin in T1547/font_drivers.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.font_drivers import FontDrivers

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_font_driver_entry_detected(tmp_path: Path) -> None:
    """Any value under the Font Drivers key produces a finding."""
    node = make_node(values={"Evil PS Driver": r"C:\Windows\evil_font.dll"})
    plugin = make_plugin(FontDrivers, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) == 1
    assert "evil_font.dll" in findings[0].value
    assert findings[0].check_id == "font_drivers"
    assert findings[0].access_gained == AccessLevel.SYSTEM
