"""Tests for the Active Setup StubPath plugin (T1547.014)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import (
    AccessLevel,
    FilterRule,
    Finding,
    Severity,
)
from pyrsistencesniper.core.profile import CheckPolicy
from pyrsistencesniper.plugins.T1547.active_setup import ActiveSetup

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_NATIVE_KEY = r"Microsoft\Active Setup\Installed Components"
_REDIRECTED_KEY = r"Wow6432Node\Microsoft\Active Setup\Installed Components"

_WOW64_ALLOW_RULE = FilterRule(
    reason="Built-in 32-bit active setup component",
    value_matches=r"\\syswow64\\",
    signer="Microsoft",
    not_lolbin=True,
)


def _component_tree(stub_path: str) -> object:
    """Build an Installed Components tree holding one component's StubPath."""
    child = make_node(name="{comp}", values={"StubPath": stub_path})
    return make_node(children={"{comp}": child})


def test_stubpath_child_produces_finding(tmp_path: Path) -> None:
    """An installed component's StubPath runs at first logon for every user."""
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_keys(plugin, {_NATIVE_KEY: _component_tree("C:\\evil\\setup.exe")})
    findings = plugin.run()
    assert len(findings) == 1
    assert "setup.exe" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "T1547" in findings[0].mitre_id
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Microsoft\Active Setup"
        r"\Installed Components\{comp}\StubPath"
    )


def test_stub_flag_values_skipped(tmp_path: Path) -> None:
    """Windows itself stores bare flags like /UserInstall here; they run nothing."""
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_keys(plugin, {_NATIVE_KEY: _component_tree("/UserInstall")})
    assert plugin.run() == []


def test_missing_stubpath_skipped(tmp_path: Path) -> None:
    """A component carrying only a Version value executes nothing."""
    child = make_node(name="{empty}", values={"Version": "1,0,0,0"})
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_keys(plugin, {_NATIVE_KEY: make_node(children={"{empty}": child})})
    assert plugin.run() == []


def test_wow6432node_component_produces_finding(tmp_path: Path) -> None:
    """32-bit Active Setup processes its own component list at first logon."""
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_keys(plugin, {_REDIRECTED_KEY: _component_tree("C:\\ProgramData\\evil.exe")})
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "C:\\ProgramData\\evil.exe"
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup"
        r"\Installed Components\{comp}\StubPath"
    )


def test_both_views_are_reported_separately(tmp_path: Path) -> None:
    """The two component lists are distinct keys, so each contributes a finding."""
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_keys(
        plugin,
        {
            _NATIVE_KEY: _component_tree("C:\\evil\\native.exe"),
            _REDIRECTED_KEY: _component_tree("C:\\evil\\wow64.exe"),
        },
    )
    findings = plugin.run()
    assert len(findings) == 2
    assert {finding.value for finding in findings} == {
        "C:\\evil\\native.exe",
        "C:\\evil\\wow64.exe",
    }


def test_undeclared_component_list_stays_quiet(tmp_path: Path) -> None:
    """A component list at a key the check never reads must produce nothing."""
    plugin = make_plugin(ActiveSetup, tmp_path)
    setup_keys(
        plugin,
        {
            r"Microsoft\Active Setup\Installed Components Backup": _component_tree(
                "C:\\evil\\setup.exe"
            )
        },
    )
    assert plugin.run() == []


def test_signed_system_component_in_either_view_is_still_reported(
    tmp_path: Path,
) -> None:
    """run() emits benign built-ins in both views; the profile, not run(), filters."""
    plugin = make_plugin(ActiveSetup, tmp_path)
    stub = "C:\\Windows\\SysWOW64\\Rundll32.exe C:\\Windows\\SysWOW64\\mscories.dll"
    setup_keys(plugin, {_REDIRECTED_KEY: _component_tree(stub)})
    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == stub


def test_wow64_allow_rule_silences_the_built_in_32_bit_component() -> None:
    """The one benign 32-bit StubPath measured live must stay below MEDIUM."""
    policy = CheckPolicy(allow=(_WOW64_ALLOW_RULE,))
    benign = Finding(
        path=(
            r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup"
            r"\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}\StubPath"
        ),
        value=(
            r"C:\Windows\SysWOW64\Rundll32.exe "
            r"C:\Windows\SysWOW64\mscories.dll,Install"
        ),
        check_id="active_setup",
        access_gained=AccessLevel.SYSTEM,
        signer="Microsoft",
        is_lolbin=False,
    )
    assert policy.classify(benign) is Severity.INFO


def test_wow64_allow_rule_leaves_a_planted_32_bit_component_reported() -> None:
    """A StubPath outside SysWOW64 must survive the allow rule and reach MEDIUM."""
    policy = CheckPolicy(allow=(_WOW64_ALLOW_RULE,))
    malicious = Finding(
        path=(
            r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup"
            r"\Installed Components\{0e8e5b1a-0000-0000-0000-000000000000}\StubPath"
        ),
        value=r"C:\ProgramData\evil.exe",
        check_id="active_setup",
        access_gained=AccessLevel.SYSTEM,
        signer="",
        is_lolbin=False,
    )
    assert policy.classify(malicious) is Severity.MEDIUM
