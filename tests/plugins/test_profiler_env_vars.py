"""Tests for CorProfiler and CoreClrProfiler plugins in T1574/profiler_env_vars.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1574.profiler_env_vars import (
    CoreClrProfiler,
    CorProfiler,
)

from .conftest import make_node, make_plugin, setup_hklm, setup_keys

_SERVICES_KEY = r"ControlSet001\Services"
_SERVICES_PATH = r"HKLM\SYSTEM\ControlSet001\Services"


class TestCorProfiler:
    """Cases for the COR_PROFILER variables the .NET Framework CLR reads."""

    def test_system_cor_profiler_detected(self, tmp_path: Path) -> None:
        """A machine-wide profiler loads into every managed process, hence SYSTEM."""
        env_node = make_node(
            values={"COR_PROFILER": "{evil-guid}", "COR_ENABLE_PROFILING": "1"}
        )
        plugin = make_plugin(CorProfiler, tmp_path)
        setup_hklm(plugin, env_node, hive_path="/fake/SYSTEM")
        findings = plugin.run()
        assert len(findings) >= 1
        assert any("evil-guid" in finding.value for finding in findings)
        assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)
        assert all("T1574" in finding.mitre_id for finding in findings)

    def test_user_cor_profiler_detected(self, tmp_path: Path) -> None:
        """A per-user Environment key reaches only that user's processes."""
        profile = UserProfile(
            username="testuser",
            profile_path=Path("/fake/Users/testuser"),
            ntuser_path=Path("/fake/ntuser.dat"),
        )
        env_node = make_node(values={"COR_PROFILER_PATH": r"C:\evil_profiler.dll"})
        plugin = make_plugin(CorProfiler, tmp_path, user_profiles=[profile])
        plugin.context.hive_path.return_value = None
        plugin.registry.open_hive.return_value = MagicMock()
        plugin.registry.load_subtree.return_value = env_node
        findings = plugin.run()
        assert len(findings) >= 1
        assert any("evil_profiler.dll" in finding.value for finding in findings)
        assert all(finding.access_gained == AccessLevel.USER for finding in findings)

    def test_env_key_without_profiler_vars(self, tmp_path: Path) -> None:
        """Every machine has an Environment key, and PATH in it is not persistence."""
        env_node = make_node(values={"PATH": r"C:\Windows"})
        plugin = make_plugin(CorProfiler, tmp_path)
        setup_hklm(plugin, env_node, hive_path="/fake/SYSTEM")
        assert plugin.run() == []


class TestCoreClrProfiler:
    """Cases for the CORECLR_ variables, the .NET Core equivalent of COR_PROFILER."""

    def test_system_coreclr_profiler_detected(self, tmp_path: Path) -> None:
        """CORECLR_ variables are a separate set, not aliases of the COR_ ones."""
        env_node = make_node(
            values={
                "CORECLR_PROFILER": "{evil-coreclr}",
                "CORECLR_ENABLE_PROFILING": "1",
            }
        )
        plugin = make_plugin(CoreClrProfiler, tmp_path)
        setup_hklm(plugin, env_node, hive_path="/fake/SYSTEM")
        findings = plugin.run()
        assert len(findings) >= 1
        assert any("evil-coreclr" in finding.value for finding in findings)
        assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)
        assert all("T1574" in finding.mitre_id for finding in findings)


def _services_plugin(cls: type, tmp_path: Path, services: dict[str, object]) -> object:
    """Wire a SYSTEM hive answering only the literal Services key path."""
    plugin = make_plugin(cls, tmp_path)
    setup_keys(plugin, {_SERVICES_KEY: make_node(children=services)})
    return plugin


class TestServiceScopedEnvironment:
    """Cases for the Environment value the SCM injects into one service."""

    def test_service_cor_profiler_detected(self, tmp_path: Path) -> None:
        """A profiler attached to W3SVC alone loads into w3wp.exe on every IIS start."""
        service = make_node(
            name="W3SVC",
            values={
                "ImagePath": r"C:\Windows\system32\svchost.exe -k iissvcs",
                "Environment": [
                    "COR_ENABLE_PROFILING=1",
                    "COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916bb}",
                    r"COR_PROFILER_PATH=C:\inetpub\evil.dll",
                ],
            },
        )
        plugin = _services_plugin(CorProfiler, tmp_path, {"W3SVC": service})
        findings = plugin.run()

        assert len(findings) == 3
        assert {finding.path for finding in findings} == {
            _SERVICES_PATH + r"\W3SVC\Environment\COR_PROFILER",
            _SERVICES_PATH + r"\W3SVC\Environment\COR_PROFILER_PATH",
            _SERVICES_PATH + r"\W3SVC\Environment\COR_ENABLE_PROFILING",
        }
        assert any(finding.value == r"C:\inetpub\evil.dll" for finding in findings)
        assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)

    def test_coreclr_variables_are_read_per_service_too(self, tmp_path: Path) -> None:
        """The .NET Core variable set gets the same per-service scope."""
        service = make_node(
            name="WAS",
            values={"Environment": [r"CORECLR_PROFILER_PATH=C:\evil\core.dll"]},
        )
        plugin = _services_plugin(CoreClrProfiler, tmp_path, {"WAS": service})
        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            _SERVICES_PATH + r"\WAS\Environment\CORECLR_PROFILER_PATH"
        )
        assert findings[0].value == r"C:\evil\core.dll"

    def test_unrelated_service_environment_stays_quiet(self, tmp_path: Path) -> None:
        """A service may legitimately set variables, and none of them is a profiler."""
        service = make_node(
            name="MSSQLSERVER",
            values={"Environment": [r"PATH=C:\Windows", r"TMP=C:\Temp"]},
        )
        plugin = _services_plugin(CorProfiler, tmp_path, {"MSSQLSERVER": service})
        assert plugin.run() == []

    def test_service_without_an_environment_value_stays_quiet(
        self, tmp_path: Path
    ) -> None:
        """No service on a stock Windows 11 host defines Environment at all."""
        service = make_node(
            name="Spooler",
            values={"ImagePath": r"C:\Windows\System32\spoolsv.exe"},
        )
        plugin = _services_plugin(CorProfiler, tmp_path, {"Spooler": service})
        assert plugin.run() == []

    def test_malformed_environment_entries_stay_quiet(self, tmp_path: Path) -> None:
        """An entry with no assignment names no variable and sets no value."""
        service = make_node(
            name="Broken",
            values={"Environment": ["COR_PROFILER", "=orphan", "COR_PROFILER_PATH=  "]},
        )
        plugin = _services_plugin(CorProfiler, tmp_path, {"Broken": service})
        assert plugin.run() == []

    def test_services_key_is_the_key_read(self, tmp_path: Path) -> None:
        """The scan reads the Services key it names, not whatever hive it is handed."""
        service = make_node(
            name="W3SVC", values={"Environment": ["COR_PROFILER={evil}"]}
        )
        plugin = make_plugin(CorProfiler, tmp_path)
        setup_keys(
            plugin,
            {
                r"ControlSet001\Control\Session Manager": make_node(
                    children={"W3SVC": service}
                )
            },
        )
        assert plugin.run() == []
