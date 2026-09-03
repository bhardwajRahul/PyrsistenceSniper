"""Tests for the LSA package and LSA protection plugins (T1547)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import FilterRule, Finding, MatchResult
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1547.lsa_packages import (
    AuthenticationPackages,
    LsaCfgFlags,
    LsaRunAsPPL,
    SecurityPackages,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_SYSTEM_HIVE = "/fake/SYSTEM"

_DECLARATIVE_CASES: list[tuple[type, str, str]] = [
    (AuthenticationPackages, "Authentication Packages", "evil_pkg"),
    (SecurityPackages, "Security Packages", "evil_ssp"),
    (LsaRunAsPPL, "RunAsPPL", "0"),
    (LsaCfgFlags, "LsaCfgFlags", "0"),
]


@pytest.mark.parametrize(
    ("plugin_cls", "value_key", "value_data"),
    _DECLARATIVE_CASES,
    ids=[case[0].__name__ for case in _DECLARATIVE_CASES],
)
def test_declarative_happy_path(
    tmp_path: Path,
    plugin_cls: type,
    value_key: str,
    value_data: str,
) -> None:
    """Each declarative plugin produces a finding when its registry value is present."""
    node = make_node(values={value_key: value_data})
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, node, hive_path=_SYSTEM_HIVE)
    findings = plugin.run()
    assert len(findings) >= 1
    assert any(value_data in finding.value for finding in findings)
    assert all("T1547" in finding.mitre_id for finding in findings)


def _run_as_ppl_rule() -> FilterRule:
    """Locate the RunAsPPL protection-enabled allowlist rule by its value pattern."""
    policy = DetectionProfile.load(None).policy_for("lsa_run_as_ppl")
    return next(rule for rule in policy.allow if "[12]" in rule.value_matches)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", MatchResult.FULL),
        ("2", MatchResult.FULL),
        ("0", MatchResult.NONE),
        ("12", MatchResult.NONE),
    ],
)
def test_run_as_ppl_rule_boundaries(value: str, expected: MatchResult) -> None:
    """The RunAsPPL rule accepts exactly 1 or 2 and rejects 0 and multi-digit values."""
    assert _run_as_ppl_rule().match_result(Finding(value=value)) == expected
