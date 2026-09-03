"""Tests for AppInitDlls multi-value parsing plugin."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.appinit_dlls import AppInitDlls

from .conftest import make_node, make_plugin


def _plugin_reading(tmp_path: Path, node: object) -> object:
    """Answer the native AppInit key with node and the 32-bit view with nothing."""
    plugin = make_plugin(AppInitDlls, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.side_effect = [node, None]
    return plugin


class TestAppInitDlls:
    """AppInitDlls parses multi-value DLL paths and LoadAppInit_DLLs context."""

    def test_happy_path_multiple_dlls(self, tmp_path: Path) -> None:
        """Every DLL in the space-separated list is loaded, so each is its own row."""
        node = make_node(
            values={
                "AppInit_DLLs": "C:\\evil.dll C:\\bad.dll",
                "LoadAppInit_DLLs": 1,
                "RequireSignedAppInit_DLLs": 0,
            }
        )

        findings = _plugin_reading(tmp_path, node).run()

        assert len(findings) == 2
        assert any("evil.dll" in finding.value for finding in findings)
        assert any("bad.dll" in finding.value for finding in findings)
        assert any("LoadAppInit_DLLs=1" in finding.value for finding in findings)
        assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)

    def test_load_appinit_disabled(self, tmp_path: Path) -> None:
        """A disabled loader can be re-enabled, so the DLL is reported as INACTIVE."""
        node = make_node(
            values={
                "AppInit_DLLs": "C:\\sneaky.dll",
                "LoadAppInit_DLLs": 0,
            }
        )

        findings = _plugin_reading(tmp_path, node).run()

        assert len(findings) == 1
        assert "INACTIVE" in findings[0].value

    def test_empty_appinit_value(self, tmp_path: Path) -> None:
        """Windows ships this value present and empty, which loads nothing."""
        node = make_node(values={"AppInit_DLLs": ""})

        assert _plugin_reading(tmp_path, node).run() == []
