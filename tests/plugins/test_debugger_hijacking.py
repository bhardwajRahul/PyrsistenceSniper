"""Tests for all 8 debugger hijacking plugins (7 declarative + 1 custom)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.debugger_hijacking import (
    AeDebug,
    AeDebugProtected,
    DotNetDbgManagedDebugger,
    LsmDebugger,
    WerDebugger,
    WerHangs,
    WerReflectDebugger,
    WerRuntimeExceptionHelperModules,
)

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_UNDECLARED_KEY = r"Microsoft\Windows NT\CurrentVersion\AeDebugArchive"

_WER_NATIVE_KEY = (
    r"Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules"
)
_WER_REDIRECTED_KEY = (
    r"Wow6432Node\Microsoft\Windows\Windows Error Reporting"
    r"\RuntimeExceptionHelperModules"
)

_DECLARATIVE_CASES: list[tuple[type, str, str, str]] = [
    (
        AeDebug,
        r"Microsoft\Windows NT\CurrentVersion\AeDebug",
        "Debugger",
        "evil.exe",
    ),
    (
        AeDebugProtected,
        r"Microsoft\Windows NT\CurrentVersion\AeDebugProtected",
        "Debugger",
        "backdoor.exe",
    ),
    (
        WerDebugger,
        r"Microsoft\Windows\Windows Error Reporting",
        "Debugger",
        "wer_evil.exe",
    ),
    (
        WerReflectDebugger,
        r"Microsoft\Windows\Windows Error Reporting",
        "ReflectDebugger",
        "reflect_evil.exe",
    ),
    (
        WerHangs,
        r"Microsoft\Windows\Windows Error Reporting\Hangs",
        "Debugger",
        "hang_evil.exe",
    ),
    (
        DotNetDbgManagedDebugger,
        r"Microsoft\.NETFramework",
        "DbgManagedDebugger",
        "dotnet_evil.exe",
    ),
    (
        LsmDebugger,
        r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsm.exe",
        "MonitorProcess",
        "lsm_evil.exe",
    ),
]

_IDS = [case[0].__name__ for case in _DECLARATIVE_CASES]


@pytest.mark.parametrize(
    ("plugin_cls", "key_path", "value_name", "value_data"),
    _DECLARATIVE_CASES,
    ids=_IDS,
)
def test_declarative_happy_path(
    tmp_path: Path,
    plugin_cls: type,
    key_path: str,
    value_name: str,
    value_data: str,
) -> None:
    """Each declarative plugin produces a finding from the native machine view."""
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_keys(plugin, {key_path: make_node(values={value_name: value_data})})
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == value_data
    assert findings[0].path == f"HKLM\\SOFTWARE\\{key_path}\\{value_name}"
    assert "T1546" in findings[0].mitre_id


@pytest.mark.parametrize(
    ("plugin_cls", "key_path", "value_name", "value_data"),
    _DECLARATIVE_CASES,
    ids=_IDS,
)
def test_declarative_reads_the_wow6432node_view(
    tmp_path: Path,
    plugin_cls: type,
    key_path: str,
    value_name: str,
    value_data: str,
) -> None:
    """32-bit code reaches these keys through the redirected view, so it is scanned."""
    redirected_key = f"Wow6432Node\\{key_path}"
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_keys(plugin, {redirected_key: make_node(values={value_name: value_data})})
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == value_data
    assert findings[0].path == f"HKLM\\SOFTWARE\\{redirected_key}\\{value_name}"
    assert findings[0].access_gained == AccessLevel.SYSTEM


@pytest.mark.parametrize(
    ("plugin_cls", "key_path", "value_name", "value_data"),
    _DECLARATIVE_CASES,
    ids=_IDS,
)
def test_declarative_ignores_a_neighbouring_key(
    tmp_path: Path,
    plugin_cls: type,
    key_path: str,
    value_name: str,
    value_data: str,
) -> None:
    """Adding the 32-bit view must not make the check read any key it likes."""
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_keys(plugin, {_UNDECLARED_KEY: make_node(values={value_name: value_data})})
    assert plugin.run() == []


class TestWerRuntimeExceptionHelperModules:
    """Cases for the one plugin here with a hand-written run() instead of targets."""

    def test_happy_path(self, tmp_path: Path) -> None:
        """RuntimeExceptionHelperModules DLL path produces a finding."""
        plugin = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
        setup_keys(
            plugin,
            {_WER_NATIVE_KEY: make_node(values={"C:\\evil\\helper.dll": 0})},
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert "helper.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert findings[0].path == (
            r"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
            r"\RuntimeExceptionHelperModules\C:\evil\helper.dll"
        )

    def test_wow6432node_module_is_reported(self, tmp_path: Path) -> None:
        """WER keeps a separate 32-bit helper-module list that is equally abusable."""
        plugin = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
        setup_keys(
            plugin,
            {_WER_REDIRECTED_KEY: make_node(values={"C:\\evil\\wow64_helper.dll": 0})},
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "C:\\evil\\wow64_helper.dll"
        assert findings[0].path.startswith(
            r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\Windows Error Reporting"
        )

    def test_both_views_are_reported_separately(self, tmp_path: Path) -> None:
        """The two helper-module lists are distinct keys holding distinct DLLs."""
        plugin = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
        setup_keys(
            plugin,
            {
                _WER_NATIVE_KEY: make_node(
                    values={"C:\\Windows\\System32\\msiwer.dll": 0}
                ),
                _WER_REDIRECTED_KEY: make_node(
                    values={"C:\\Windows\\SysWOW64\\msiwer.dll": 0}
                ),
            },
        )
        findings = plugin.run()
        assert len(findings) == 2
        assert {finding.value for finding in findings} == {
            "C:\\Windows\\System32\\msiwer.dll",
            "C:\\Windows\\SysWOW64\\msiwer.dll",
        }

    def test_empty_value_name_skipped(self, tmp_path: Path) -> None:
        """The value name is the DLL path, so a blank one names nothing to report."""
        plugin = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
        setup_keys(
            plugin,
            {_WER_NATIVE_KEY: make_node(values={"  ": 0, "C:\\real.dll": 1})},
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert "real.dll" in findings[0].value

    def test_undeclared_key_stays_quiet(self, tmp_path: Path) -> None:
        """A helper-module list somewhere else is not the key WER actually reads."""
        plugin = make_plugin(WerRuntimeExceptionHelperModules, tmp_path)
        setup_keys(
            plugin,
            {
                r"Microsoft\Windows\Windows Error Reporting\Hangs": make_node(
                    values={"C:\\evil\\helper.dll": 0}
                )
            },
        )
        assert plugin.run() == []
