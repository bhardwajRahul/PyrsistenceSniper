"""Tests for DiskCleanupHandler CLSID enumeration + InprocServer32 resolution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.disk_cleanup import DiskCleanupHandler

from .conftest import make_node, make_plugin


def _plugin_reading(tmp_path: Path, *answers: object) -> object:
    """Answer the VolumeCaches read, then the CLSID read, with the nodes given."""
    plugin = make_plugin(DiskCleanupHandler, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.side_effect = list(answers)
    return plugin


class TestDiskCleanupHandler:
    """DiskCleanupHandler enumerates VolumeCaches handlers and resolves CLSIDs."""

    def test_happy_path_handler_with_inproc(self, tmp_path: Path) -> None:
        """A handler CLSID resolving to a DLL names the code cleanmgr.exe loads."""
        handler_node = make_node(name="OldFiles", values={"(Default)": "{CLSID-1}"})
        tree = make_node(children={"OldFiles": handler_node})
        inproc_node = make_node(
            name="InprocServer32",
            values={"(Default)": "C:\\evil.dll"},
        )

        findings = _plugin_reading(tmp_path, tree, inproc_node).run()

        assert len(findings) == 1
        assert "evil.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_handler_without_inproc_resolution(self, tmp_path: Path) -> None:
        """A CLSID registering no server names no DLL, so there is nothing to report."""
        handler_node = make_node(name="Broken", values={"(Default)": "{CLSID-X}"})
        tree = make_node(children={"Broken": handler_node})

        assert _plugin_reading(tmp_path, tree, None).run() == []

    def test_handler_without_clsid(self, tmp_path: Path) -> None:
        """A (Default) that is not a CLSID registers no COM server to resolve."""
        handler_node = make_node(name="NoClsid", values={"(Default)": "not-a-clsid"})
        tree = make_node(children={"NoClsid": handler_node})

        plugin = make_plugin(DiskCleanupHandler, tmp_path)
        plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
        plugin.registry.open_hive.return_value = MagicMock()
        plugin.registry.load_subtree.return_value = tree

        assert plugin.run() == []
