"""Tests for the AppCertDlls declarative plugin (T1546.009)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1546.appcert_dlls import AppCertDlls

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SYSTEM_HIVE = "/fake/SYSTEM"


def test_appcert_dlls_happy_path(tmp_path: Path) -> None:
    """Any AppCertDlls value names a DLL loaded into every CreateProcess call."""
    node = make_node(values={"evil.dll": r"C:\evil.dll"})
    plugin = make_plugin(AppCertDlls, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)

    findings = plugin.run()

    assert len(findings) == 1
    assert r"C:\evil.dll" in findings[0].value
    assert findings[0].path.startswith("HKLM\\SYSTEM")
