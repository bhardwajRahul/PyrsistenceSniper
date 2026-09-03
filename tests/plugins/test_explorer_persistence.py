"""Tests for the Explorer persistence plugins: BHO, Load, and AppKey (T1547.001)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.explorer_persistence import (
    ExplorerAppKey,
    ExplorerBrowserHelperObjects,
    ExplorerLoad,
)

from .conftest import make_node, make_plugin, setup_hklm


def _plugin_reading(cls: type, tmp_path: Path, *answers: object) -> object:
    """Answer successive load_subtree calls with the nodes given, in order."""
    plugin = make_plugin(cls, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.side_effect = list(answers)
    return plugin


class TestBrowserHelperObjects:
    """Cases for browser helper objects, named by DLL once the CLSID resolves."""

    def test_bho_with_inprocserver32_resolved(self, tmp_path: Path) -> None:
        """A BHO is reported by the DLL Explorer loads, not by its CLSID."""
        tree = make_node(children={"{BHO-CLSID}": make_node(name="{BHO-CLSID}")})
        inproc_node = make_node(values={"(Default)": r"C:\bho.dll"})

        findings = _plugin_reading(
            ExplorerBrowserHelperObjects, tmp_path, tree, inproc_node
        ).run()

        assert len(findings) == 1
        assert "bho.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_bho_without_inprocserver32_shows_clsid(self, tmp_path: Path) -> None:
        """An unresolvable CLSID is still reported; a dangling BHO is itself suspect."""
        tree = make_node(children={"{ORPHAN-BHO}": make_node(name="{ORPHAN-BHO}")})

        findings = _plugin_reading(
            ExplorerBrowserHelperObjects, tmp_path, tree, None
        ).run()

        assert len(findings) == 1
        assert "{ORPHAN-BHO}" in findings[0].value


class TestExplorerLoad:
    """Cases for the Explorer Load value, a plain declarative check."""

    def test_load_value_present(self, tmp_path: Path) -> None:
        """The Load value runs at every logon that starts Explorer."""
        node = make_node(values={"Load": r"C:\evil\payload.exe"})

        plugin = make_plugin(ExplorerLoad, tmp_path)
        plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
        plugin.registry.open_hive.return_value = MagicMock()
        plugin.registry.load_subtree.return_value = node

        findings = plugin.run()

        assert len(findings) >= 1
        assert any("payload.exe" in finding.value for finding in findings)


class TestAppKeys:
    """Cases for AppKey children, each carrying two independent launch values."""

    def test_app_key_with_shell_execute(self, tmp_path: Path) -> None:
        """ShellExecute binds a keyboard key to a command line, which is execution."""
        child = make_node(name="18", values={"ShellExecute": r"C:\evil.exe"})
        plugin = make_plugin(ExplorerAppKey, tmp_path)
        setup_hklm(plugin, make_node(children={"18": child}))

        findings = plugin.run()

        assert len(findings) == 1
        assert "evil.exe" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_app_key_with_association(self, tmp_path: Path) -> None:
        """Association reaches the same execution through a file-type handler."""
        child = make_node(name="7", values={"Association": "evilapp"})
        plugin = make_plugin(ExplorerAppKey, tmp_path)
        setup_hklm(plugin, make_node(children={"7": child}))

        findings = plugin.run()

        assert len(findings) == 1
        assert "evilapp" in findings[0].value

    def test_app_key_with_both_values(self, tmp_path: Path) -> None:
        """The two values are independent launch paths, so each is its own finding."""
        child = make_node(
            name="15",
            values={"ShellExecute": r"C:\app.exe", "Association": "myapp"},
        )
        plugin = make_plugin(ExplorerAppKey, tmp_path)
        setup_hklm(plugin, make_node(children={"15": child}))

        assert len(plugin.run()) == 2
