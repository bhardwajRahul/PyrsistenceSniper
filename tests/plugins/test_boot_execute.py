"""Tests for the boot and Session Manager execute plugins (T1547.001)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import Finding, MatchResult
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1547.boot_execute import (
    BootExecute,
    PlatformExecute,
    S0InitialCommand,
    ServiceControlManagerExtension,
    SessionManagerExecute,
    SessionManagerSubSystems,
    SetupExecute,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SYSTEM_HIVE = "/fake/SYSTEM"

_DECLARATIVE_CASES: list[tuple[type, str, str, str]] = [
    (BootExecute, "BootExecute", "evil.exe", _SYSTEM_HIVE),
    (SetupExecute, "SetupExecute", "setup_evil.exe", _SYSTEM_HIVE),
    (PlatformExecute, "PlatformExecute", "plat_evil.exe", _SYSTEM_HIVE),
    (SessionManagerExecute, "Execute", "smexec.exe", _SYSTEM_HIVE),
    (S0InitialCommand, "S0InitialCommand", "s0cmd.exe", _SYSTEM_HIVE),
    (ServiceControlManagerExtension, "evil_dll", r"C:\evil.dll", _SYSTEM_HIVE),
    (
        SessionManagerSubSystems,
        "Windows",
        r"%SystemRoot%\system32\evil.exe",
        _SYSTEM_HIVE,
    ),
]


@pytest.mark.parametrize(
    ("plugin_cls", "value_key", "value_data", "hive_path"),
    _DECLARATIVE_CASES,
    ids=[case[0].__name__ for case in _DECLARATIVE_CASES],
)
def test_declarative_happy_path(
    tmp_path: Path,
    plugin_cls: type,
    value_key: str,
    value_data: str,
    hive_path: str,
) -> None:
    """Each declarative plugin produces a finding when its registry value is present."""
    node = make_node(values={value_key: value_data})
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, node, hive_path=hive_path)
    findings = plugin.run()
    assert len(findings) >= 1
    assert any(value_data in finding.value for finding in findings)
    assert all("T1547" in finding.mitre_id for finding in findings)


class TestSubSystemsFilterRule:
    """Cases for the profile rule that allows a signed csrss.exe and nothing else."""

    rule = next(
        allow_rule
        for allow_rule in DetectionProfile.load(None)
        .policy_for("session_manager_subsystems")
        .allow
        if "csrss" in allow_rule.value_matches
    )

    @pytest.mark.parametrize(
        ("value", "signer", "expected"),
        [
            (
                r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows",
                "Microsoft Windows",
                MatchResult.FULL,
            ),
            (
                r"%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows",
                "",
                MatchResult.PARTIAL,
            ),
            (
                r"%SystemRoot%\system32\evil.exe",
                "Microsoft Windows",
                MatchResult.NONE,
            ),
        ],
        ids=["csrss_signed_full", "csrss_unsigned_partial", "evil_exe_none"],
    )
    def test_match_result(self, value: str, signer: str, expected: MatchResult) -> None:
        """An unsigned csrss line stays partial, so a swapped binary is not allowed."""
        finding = Finding(value=value, signer=signer)
        assert self.rule.match_result(finding) == expected
