"""Tests for the DotNetFrameworkProfiler plugin in T1574/dotnet_profiler_registry.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1574.dotnet_profiler_registry import (
    DotNetFrameworkProfiler,
)

from .conftest import make_node, make_plugin, make_user_profiles, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_MACHINE_KEY = r"Microsoft\.NETFramework"
_REDIRECTED_KEY = r"Wow6432Node\Microsoft\.NETFramework"
_USER_KEY = r"SOFTWARE\Microsoft\.NETFramework"

_PROFILER_VALUES: dict[str, object] = {
    "COR_PROFILER": "{evil-clsid}",
    "COR_PROFILER_PATH": r"C:\evil_profiler.dll",
    "COR_ENABLE_PROFILING": "1",
}


def test_profiler_values_detected(tmp_path: Path) -> None:
    """All three COR_* values in the .NETFramework key produce findings."""
    plugin = make_plugin(DotNetFrameworkProfiler, tmp_path)
    setup_keys(plugin, {_MACHINE_KEY: make_node(values=_PROFILER_VALUES)})
    findings = plugin.run()
    assert len(findings) == 3
    assert any("evil-clsid" in finding.value for finding in findings)
    assert any("evil_profiler.dll" in finding.value for finding in findings)
    assert all(finding.check_id == "dotnet_framework_profiler" for finding in findings)
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)
    assert all(
        finding.path.startswith(r"HKLM\SOFTWARE\Microsoft\.NETFramework\COR_")
        for finding in findings
    )


def test_wow6432node_profiler_values_detected(tmp_path: Path) -> None:
    """The 32-bit CLR reads the redirected key, so a profiler there is persistence."""
    plugin = make_plugin(DotNetFrameworkProfiler, tmp_path)
    setup_keys(plugin, {_REDIRECTED_KEY: make_node(values=_PROFILER_VALUES)})
    findings = plugin.run()
    assert len(findings) == 3
    assert all(
        finding.path.startswith(
            r"HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\COR_"
        )
        for finding in findings
    )
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)


def test_per_user_profiler_values_detected(tmp_path: Path) -> None:
    """The HKCU copy of the key needs no administrative rights and is checked."""
    plugin = make_plugin(
        DotNetFrameworkProfiler, tmp_path, user_profiles=make_user_profiles("alice")
    )
    setup_keys(plugin, {_USER_KEY: make_node(values=_PROFILER_VALUES)})
    findings = plugin.run()
    assert len(findings) == 3
    assert all(finding.access_gained is AccessLevel.USER for finding in findings)
    assert all(
        finding.path.startswith(r"HKU\alice\SOFTWARE\Microsoft\.NETFramework\COR_")
        for finding in findings
    )


def test_non_profiler_values_stay_quiet(tmp_path: Path) -> None:
    """A clean .NETFramework key carries InstallRoot and nothing this check reports."""
    plugin = make_plugin(
        DotNetFrameworkProfiler, tmp_path, user_profiles=make_user_profiles("alice")
    )
    clean = make_node(
        values={
            "InstallRoot": r"C:\Windows\Microsoft.NET\Framework64\ ",
            "Enable64Bit": 1,
            "UseRyuJIT": 1,
        }
    )
    setup_keys(
        plugin,
        {_MACHINE_KEY: clean, _REDIRECTED_KEY: clean, _USER_KEY: clean},
    )
    assert plugin.run() == []


def test_undeclared_key_stays_quiet(tmp_path: Path) -> None:
    """COR_* values under a key the CLR never consults must not be reported."""
    plugin = make_plugin(
        DotNetFrameworkProfiler, tmp_path, user_profiles=make_user_profiles("alice")
    )
    setup_keys(
        plugin,
        {r"Microsoft\.NETFramework\v4.0.30319": make_node(values=_PROFILER_VALUES)},
    )
    assert plugin.run() == []
