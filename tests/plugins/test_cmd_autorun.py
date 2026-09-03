"""Tests for the CmdAutoRun plugin in T1546/cmd_autorun.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1546.cmd_autorun import CmdAutoRun

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    """An AutoRun value under Command Processor produces an HKLM finding."""
    node = make_node(values={"AutoRun": r"C:\evil_autorun.cmd"})
    plugin = make_plugin(CmdAutoRun, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) == 1
    assert "evil_autorun.cmd" in findings[0].value
    assert findings[0].check_id == "cmd_autorun"
    assert findings[0].path.startswith("HKLM")
