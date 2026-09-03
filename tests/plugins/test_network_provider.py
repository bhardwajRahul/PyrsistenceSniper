"""Tests for the NetworkProviderDll plugin (T1556) and its allowlist rule."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import AccessLevel, FilterRule, Finding, MatchResult
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1556.network_provider import NetworkProviderDll

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def _services_plugin(tmp_path: Path, services: dict[str, object]) -> NetworkProviderDll:
    """Build the plugin over a Services key holding the given service subkeys."""
    plugin = make_plugin(NetworkProviderDll, tmp_path)
    setup_hklm(plugin, make_node(children=services), hive_path="/fake/SYSTEM")
    return plugin


def test_happy_path(tmp_path: Path) -> None:
    """A ProviderPath DLL loads into the logon path, so it is a SYSTEM-level hit."""
    provider_node = make_node(
        name="NetworkProvider",
        values={"ProviderPath": r"C:\evil_np.dll"},
    )
    service_node = make_node(
        name="EvilSvc", children={"NetworkProvider": provider_node}
    )

    findings = _services_plugin(tmp_path, {"EvilSvc": service_node}).run()

    assert len(findings) == 1
    assert "evil_np.dll" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_service_without_network_provider(tmp_path: Path) -> None:
    """Most services have no NetworkProvider subkey and must not be reported."""
    service_node = make_node(name="PlainSvc", values={"ImagePath": "svc.exe"})

    assert _services_plugin(tmp_path, {"PlainSvc": service_node}).run() == []


def test_network_provider_without_path(tmp_path: Path) -> None:
    """A NetworkProvider subkey with no ProviderPath loads no DLL, so no finding."""
    provider_node = make_node(name="NetworkProvider", values={"Name": "test"})
    service_node = make_node(name="SvcNP", children={"NetworkProvider": provider_node})

    assert _services_plugin(tmp_path, {"SvcNP": service_node}).run() == []


def test_no_subtree(tmp_path: Path) -> None:
    """A missing SYSTEM hive is a clean absence, not a scan failure."""
    plugin = make_plugin(NetworkProviderDll, tmp_path)
    plugin.context.hive_path.return_value = None

    assert plugin.run() == []


def _default_provider_rule() -> FilterRule:
    """Locate the default network provider allowlist rule by its DLL list pattern."""
    policy = DetectionProfile.load(None).policy_for("network_provider_dll")
    return next(rule for rule in policy.allow if "ntlanman" in rule.value_matches)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (r"C:\Windows\system32\drprov.dll", MatchResult.FULL),
        (r"C:\Windows\system32\ntlanman.dll", MatchResult.FULL),
        (r"C:\evil.dll", MatchResult.NONE),
    ],
    ids=["drprov", "ntlanman", "evil-dll"],
)
def test_default_provider_rule(value: str, expected: MatchResult) -> None:
    """The rule allows stock signed provider DLLs and rejects unknown paths."""
    finding = Finding(value=value, signer="Microsoft Windows")
    assert _default_provider_rule().match_result(finding) == expected
