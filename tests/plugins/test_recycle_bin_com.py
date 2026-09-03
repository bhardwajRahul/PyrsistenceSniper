"""Tests for the RecycleBinComExtension plugin in T1546/recycle_bin_com.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.recycle_bin_com import RecycleBinComExtension

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_hijacked_shell_verb_command_detected(tmp_path: Path) -> None:
    """Explorer runs the verb command, so each hijacked verb is its own hit."""
    node = make_node(values={"(Default)": r"C:\evil_recycler.exe"})
    plugin = make_plugin(RecycleBinComExtension, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) == 3
    assert all("evil_recycler.exe" in finding.value for finding in findings)
    assert all(finding.check_id == "recycle_bin_com_extension" for finding in findings)
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)
    paths = "\n".join(finding.path for finding in findings)
    assert r"{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command" in paths
    assert r"{645FF040-5081-101B-9F08-00AA002F954E}\shell\empty\command" in paths
    assert r"{645FF040-5081-101B-9F08-00AA002F954E}\shell\explore\command" in paths


def test_shellex_handler_subkey_detected(tmp_path: Path) -> None:
    """A planted handler subkey produces a recurse finding per shellex target."""
    handler = make_node(
        name="EvilHandler",
        values={"(Default)": "{deadbeef-0000-0000-0000-000000000000}"},
    )
    tree = make_node(children={"EvilHandler": handler})
    plugin = make_plugin(RecycleBinComExtension, tmp_path)
    setup_hklm(plugin, tree, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) == 2
    assert all(
        "{deadbeef-0000-0000-0000-000000000000}" in finding.value
        for finding in findings
    )
    assert all(finding.check_id == "recycle_bin_com_extension" for finding in findings)
    paths = "\n".join(finding.path for finding in findings)
    assert r"shellex\ContextMenuHandlers\EvilHandler" in paths
    assert r"shellex\DragDropHandlers\EvilHandler" in paths
