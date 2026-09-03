"""Tests for the NetshHelper plugin in T1546/netsh_helper.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1546.netsh_helper import NetshHelper

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    """netsh.exe loads every registered helper DLL each time it is run."""
    node = make_node(values={"evilhelper": r"C:\evil_netsh.dll"})
    plugin = make_plugin(NetshHelper, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) == 1
    assert "evil_netsh.dll" in findings[0].value
    assert findings[0].check_id == "netsh_helper"
