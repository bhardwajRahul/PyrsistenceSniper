"""Tests for the OfficeTestDll plugin in T1137/office_test_dll.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1137.office_test_dll import OfficeTestDll

from .conftest import make_node, make_plugin, make_user_profiles, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_NATIVE_KEY = r"Microsoft\Office Test\Special\Perf"
_REDIRECTED_KEY = r"Wow6432Node\Microsoft\Office Test\Special\Perf"
_USER_KEY = r"SOFTWARE\Microsoft\Office Test\Special\Perf"


def test_perf_key_dll_detected(tmp_path: Path) -> None:
    """A DLL planted in the Office Test Perf key produces an HKLM finding."""
    node = make_node(values={"(Default)": r"C:\evil_officetest.dll"})
    plugin = make_plugin(OfficeTestDll, tmp_path)
    setup_keys(plugin, {_NATIVE_KEY: node})
    findings = plugin.run()
    assert len(findings) == 1
    assert "evil_officetest.dll" in findings[0].value
    assert findings[0].check_id == "office_test_dll"
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert findings[0].path == r"HKLM\SOFTWARE\Microsoft\Office Test\Special\Perf"


def test_wow6432node_perf_key_dll_detected(tmp_path: Path) -> None:
    """32-bit Office reads the redirected Perf key, so it must be scanned too."""
    node = make_node(values={"(Default)": r"C:\ProgramData\perf.dll"})
    plugin = make_plugin(OfficeTestDll, tmp_path)
    setup_keys(plugin, {_REDIRECTED_KEY: node})
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == r"C:\ProgramData\perf.dll"
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Office Test\Special\Perf"
    )


def test_both_machine_views_are_reported_separately(tmp_path: Path) -> None:
    """The native and redirected Perf keys are distinct locations on disk."""
    plugin = make_plugin(OfficeTestDll, tmp_path)
    setup_keys(
        plugin,
        {
            _NATIVE_KEY: make_node(values={"(Default)": r"C:\evil\native.dll"}),
            _REDIRECTED_KEY: make_node(values={"(Default)": r"C:\evil\wow64.dll"}),
        },
    )
    findings = plugin.run()
    assert len(findings) == 2
    assert {finding.value for finding in findings} == {
        r"C:\evil\native.dll",
        r"C:\evil\wow64.dll",
    }


def test_per_user_perf_key_dll_detected(tmp_path: Path) -> None:
    """The per-user copy of the Perf key needs no administrative rights to write."""
    node = make_node(values={"(Default)": r"C:\Users\alice\perf.dll"})
    plugin = make_plugin(
        OfficeTestDll, tmp_path, user_profiles=make_user_profiles("alice")
    )
    setup_keys(plugin, {_USER_KEY: node})
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].access_gained is AccessLevel.USER
    assert findings[0].path == (
        r"HKU\alice\SOFTWARE\Microsoft\Office Test\Special\Perf"
    )


def test_absent_perf_key_stays_quiet(tmp_path: Path) -> None:
    """A clean host has no Perf key in either view, so nothing is reported."""
    plugin = make_plugin(OfficeTestDll, tmp_path)
    setup_keys(
        plugin,
        {
            r"Microsoft\Office\16.0\Word": make_node(
                values={"(Default)": r"C:\Program Files\Microsoft Office\winword.exe"}
            )
        },
    )
    assert plugin.run() == []
