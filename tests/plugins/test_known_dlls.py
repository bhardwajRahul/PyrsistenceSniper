"""Tests for the T1574.001 KnownDLLs plugins and the DLL search-order settings."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import (
    AccessLevel,
    FilterRule,
    Finding,
    MatchResult,
    Severity,
)
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1574.known_dlls import (
    DllSearchMode,
    ExcludeFromKnownDlls,
    KnownDlls,
)

from .conftest import make_node, make_plugin, setup_hklm, setup_keys

_SESSION_MANAGER_KEY = r"ControlSet001\Control\Session Manager"
_SESSION_MANAGER_PATH = r"HKLM\SYSTEM\ControlSet001\Control\Session Manager"

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    """A non-stock KnownDLLs entry is reported: the loader preloads it everywhere."""
    node = make_node(values={"evil": "evil.dll"})
    plugin = make_plugin(KnownDlls, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SYSTEM")
    findings = plugin.run()
    assert len(findings) == 1
    assert "evil.dll" in findings[0].value
    assert "T1574" in findings[0].mitre_id


def test_empty_name_skipped(tmp_path: Path) -> None:
    """A blank value name names no DLL to hijack, so nothing is reported."""
    node = make_node(values={"  ": "blank.dll"})
    plugin = make_plugin(KnownDlls, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SYSTEM")
    assert plugin.run() == []


def test_multiple_entries(tmp_path: Path) -> None:
    """Each entry becomes its own finding; the scan does not stop at the first."""
    node = make_node(values={"kernel32": "kernel32.dll", "ntdll": "ntdll.dll"})
    plugin = make_plugin(KnownDlls, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SYSTEM")
    assert len(plugin.run()) == 2


def test_no_subtree(tmp_path: Path) -> None:
    """An image with no SYSTEM hive is a clean absence, not a scan failure."""
    plugin = make_plugin(KnownDlls, tmp_path)
    plugin.context.hive_path.return_value = None
    assert plugin.run() == []


def _known_dll_rule() -> FilterRule:
    """Locate the known-DLL name allowlist rule by its value pattern."""
    policy = DetectionProfile.load(None).policy_for("known_dlls")
    return next(rule for rule in policy.allow if "kernel32" in rule.value_matches)


_RULE_CASES: list[tuple[str, str, MatchResult]] = [
    ("SHELL32.dll", "Microsoft Windows", MatchResult.FULL),
    ("kernel32.dll", "Microsoft Windows", MatchResult.FULL),
    ("SHELL32.dll", "", MatchResult.PARTIAL),
    ("evil.dll", "Microsoft Windows", MatchResult.NONE),
]


@pytest.mark.parametrize(
    ("value", "signer", "expected"),
    _RULE_CASES,
    ids=["signed-full", "case-insensitive", "unsigned-partial", "unknown-none"],
)
def test_known_dll_rule(value: str, signer: str, expected: MatchResult) -> None:
    """Stock DLL names match in any case; unsigned hits degrade to PARTIAL."""
    finding = Finding(value=value, signer=signer)
    assert _known_dll_rule().match_result(finding) == expected


def _session_manager_plugin(
    cls: type, tmp_path: Path, values: dict[str, object]
) -> object:
    """Wire a SYSTEM hive that answers only the literal Session Manager key path."""
    plugin = make_plugin(cls, tmp_path)
    setup_keys(plugin, {_SESSION_MANAGER_KEY: make_node(values=values)})
    return plugin


class TestExcludeFromKnownDlls:
    """Cases for the value that drops a DLL out of the KnownDLLs namespace."""

    def test_excluded_dll_is_reported(self, tmp_path: Path) -> None:
        """Each excluded name re-opens that DLL to search-order hijacking."""
        plugin = _session_manager_plugin(
            ExcludeFromKnownDlls,
            tmp_path,
            {"ExcludeFromKnownDlls": ["wldp.dll", "version.dll"]},
        )
        findings = plugin.run()
        assert [finding.value for finding in findings] == ["wldp.dll", "version.dll"]
        assert all(
            finding.path == _SESSION_MANAGER_PATH + r"\ExcludeFromKnownDlls"
            for finding in findings
        )
        assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)

    def test_empty_multi_string_stays_quiet(self, tmp_path: Path) -> None:
        """Windows 11 ships this value present and empty, which must report nothing."""
        plugin = _session_manager_plugin(
            ExcludeFromKnownDlls, tmp_path, {"ExcludeFromKnownDlls": []}
        )
        assert plugin.run() == []

    def test_absent_value_stays_quiet(self, tmp_path: Path) -> None:
        """A Session Manager key without the value excludes nothing."""
        plugin = _session_manager_plugin(
            ExcludeFromKnownDlls, tmp_path, {"ProtectionMode": 1}
        )
        assert plugin.run() == []

    def test_knowndlls_subkey_is_not_the_key_read(self, tmp_path: Path) -> None:
        """The value sits on Session Manager itself, not on its KnownDLLs subkey."""
        plugin = make_plugin(ExcludeFromKnownDlls, tmp_path)
        setup_keys(
            plugin,
            {
                _SESSION_MANAGER_KEY + r"\KnownDLLs": make_node(
                    values={"ExcludeFromKnownDlls": ["wldp.dll"]}
                )
            },
        )
        assert plugin.run() == []

    def test_no_system_hive(self, tmp_path: Path) -> None:
        """An image with no SYSTEM hive is a clean absence, not a scan failure."""
        plugin = make_plugin(ExcludeFromKnownDlls, tmp_path)
        plugin.context.hive_path.return_value = None
        assert plugin.run() == []


_SEARCH_MODE_CASES: list[tuple[str, object, bool]] = [
    ("SafeDllSearchMode", 0, True),
    ("SafeDllSearchMode", "0", True),
    ("SafeDllSearchMode", 1, False),
    ("SafeDllSearchMode", "not a number", False),
    ("CWDIllegalInDllSearch", 0, True),
    ("CWDIllegalInDllSearch", 1, False),
    ("CWDIllegalInDllSearch", 0xFFFFFFFF, False),
]


class TestDllSearchMode:
    """Cases for the Session Manager flags that widen the DLL search order."""

    @pytest.mark.parametrize(
        ("flag_name", "raw_value", "expected_finding"),
        _SEARCH_MODE_CASES,
        ids=[
            "safe-disabled",
            "safe-disabled-as-string",
            "safe-enabled",
            "safe-garbage",
            "cwd-restored",
            "cwd-webdav-blocked",
            "cwd-removed",
        ],
    )
    def test_flag_fires_only_on_its_weakening_value(
        self,
        tmp_path: Path,
        flag_name: str,
        raw_value: object,
        expected_finding: bool,
    ) -> None:
        """Only the value that widens the search order is a finding."""
        plugin = _session_manager_plugin(
            DllSearchMode, tmp_path, {flag_name: raw_value}
        )
        findings = plugin.run()
        assert bool(findings) is expected_finding
        if expected_finding:
            assert findings[0].path == _SESSION_MANAGER_PATH + "\\" + flag_name
            assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_neither_flag_set_stays_quiet(self, tmp_path: Path) -> None:
        """Windows 11 sets neither flag, so a stock host reports nothing here."""
        plugin = _session_manager_plugin(
            DllSearchMode, tmp_path, {"ProtectionMode": 1, "GlobalFlag": 0}
        )
        assert plugin.run() == []

    def test_both_flags_disabled_are_reported_separately(self, tmp_path: Path) -> None:
        """Two weakened flags are two distinct changes an analyst must see."""
        plugin = _session_manager_plugin(
            DllSearchMode,
            tmp_path,
            {"SafeDllSearchMode": 0, "CWDIllegalInDllSearch": 0},
        )
        assert len(plugin.run()) == 2

    def test_no_system_hive(self, tmp_path: Path) -> None:
        """An image with no SYSTEM hive is a clean absence, not a scan failure."""
        plugin = make_plugin(DllSearchMode, tmp_path)
        plugin.context.hive_path.return_value = None
        assert plugin.run() == []


def test_search_order_settings_are_not_suppressed_by_the_known_dlls_allowlist() -> None:
    """Their own check ids keep them out of reach of the unanchored known_dlls rule."""
    profile = DetectionProfile.load(None)
    excluded_dll = Finding(
        value="wldp.dll",
        check_id="exclude_from_known_dlls",
        signer="Microsoft Windows",
        exists=True,
        is_lolbin=False,
    )
    disabled_flag = Finding(
        value="0",
        check_id="dll_search_mode",
        signer="",
        is_lolbin=False,
    )

    assert profile.policy_for("exclude_from_known_dlls").classify(excluded_dll) is (
        Severity.MEDIUM
    )
    assert profile.policy_for("dll_search_mode").classify(disabled_flag) is (
        Severity.MEDIUM
    )
    assert profile.policy_for("known_dlls").classify(excluded_dll) < Severity.MEDIUM
