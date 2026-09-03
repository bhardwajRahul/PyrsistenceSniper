"""Tests for the VbaMonitors CLSID InprocServer32 lookup (T1137)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1137.vba_monitors import VbaMonitors

from .conftest import make_node, make_plugin, make_user_profiles, setup_usrclass


def test_inprocserver32_value_produces_finding(tmp_path: Path) -> None:
    """A monitor CLSID loads its DLL into every Office process on the host."""
    inproc_node = make_node(values={"(Default)": "C:\\evil_vba.dll"})
    plugin = make_plugin(VbaMonitors, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive
    plugin.registry.load_subtree.return_value = inproc_node

    findings = plugin.run()

    assert len(findings) == 2
    for finding in findings:
        assert "evil_vba.dll" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "InprocServer32" in finding.path
    assert len({finding.path for finding in findings}) == 2


def test_clsid_exists_no_inproc_value_returns_empty(tmp_path: Path) -> None:
    """An InprocServer32 key with no default value names no DLL to load."""
    empty_node = make_node(values={})
    plugin = make_plugin(VbaMonitors, tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive
    plugin.registry.load_subtree.return_value = empty_node

    findings = plugin.run()
    assert findings == []


_VBA_CLSID = "{13B4E945-2B11-4B60-94A9-B6CDE52F6F93}"


def test_per_user_monitor_read_from_the_hive_root(tmp_path: Path) -> None:
    """The per-user lookup addresses the hive at its root, with no classes prefix."""
    plugin = make_plugin(
        VbaMonitors, tmp_path, user_profiles=make_user_profiles("victim")
    )
    lookup = f"CLSID\\{_VBA_CLSID}\\InprocServer32"
    setup_usrclass(plugin, {lookup: make_node(values={"(Default)": "evil.dll"})})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].access_gained == AccessLevel.USER
    assert findings[0].path == f"HKU\\victim\\Software\\Classes\\{lookup}"


def test_per_user_monitor_not_read_from_a_prefixed_path(tmp_path: Path) -> None:
    """A hive answering only the prefixed path yields nothing, as on real images."""
    plugin = make_plugin(
        VbaMonitors, tmp_path, user_profiles=make_user_profiles("victim")
    )
    prefixed = f"Software\\Classes\\CLSID\\{_VBA_CLSID}\\InprocServer32"
    setup_usrclass(plugin, {prefixed: make_node(values={"(Default)": "evil.dll"})})

    assert plugin.run() == []
