"""Tests for the RunKeys plugin (T1547.001) and the hive wiring it uses."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import AccessLevel, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1547.run_keys import RunKeys

from .conftest import (
    make_node,
    make_plugin,
    make_user_profiles,
    setup_hklm,
    setup_keys,
)

if TYPE_CHECKING:
    from pathlib import Path

    from pyrsistencesniper.core.models import Finding

_SOFTWARE_HIVE = "/fake/SOFTWARE"
_HKLM_RUN_KEY = r"Microsoft\Windows\CurrentVersion\Run"
_HKLM_RUNEX_KEY = r"Microsoft\Windows\CurrentVersion\RunEx"
_HKLM_RUNONCEEX_KEY = r"Microsoft\Windows\CurrentVersion\RunOnceEx"
_HKLM_WOW64_RUNONCEEX_KEY = r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx"
_HKCU_RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_HKCU_RUNONCEEX_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
_DECOY_KEY = r"Decoy\Path\No\Check\Declares"
_EVIL_COMMAND = r"C:\Users\alice\AppData\Roaming\evil.exe"
_ONEDRIVE_COMMAND = (
    r'"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'
)
_SECTION_COMMAND = r"C:\ProgramData\evil.dll|Install"
_SECTION_DEPEND_DLL = r"C:\ProgramData\loader.dll"
_SECTION_CAPTION = "Installing Windows updates..."
_EDGE_WEBVIEW_COMMAND = (
    r'"C:\Program Files (x86)\Microsoft\EdgeWebView\Application'
    r'\151.0.4129.107\Installer\setup.exe" --uninstall'
)

_DECLARED_MACHINE_KEYS = (
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunEx",
    r"Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx",
)


def _shipped_severity(finding: Finding) -> Severity:
    """Classify a finding with the shipped run_keys policy, as a real scan would."""
    return DetectionProfile.load(None).policy_for("run_keys").classify(finding)


def _section_node(values: dict[str, object], section: str = "0001") -> object:
    """Build a RunOnceEx key holding one ordered section subkey with those values."""
    return make_node(children={section: make_node(name=section, values=values)})


def test_run_keys_happy_path(tmp_path: Path) -> None:
    """Wildcard value under the HKLM Run key produces findings (non-allow-listed)."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(plugin, {_HKLM_RUN_KEY: make_node(values={"EvilApp": "evil.exe"})})

    findings = plugin.run()

    hklm_findings = [finding for finding in findings if finding.path.startswith("HKLM")]
    assert len(hklm_findings) == 1, "Expected exactly one HKLM finding for evil.exe"
    assert hklm_findings[0].value == "evil.exe"
    assert (
        hklm_findings[0].path
        == r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp"
    )
    assert hklm_findings[0].access_gained is AccessLevel.SYSTEM


@pytest.mark.parametrize("key_path", _DECLARED_MACHINE_KEYS)
def test_declared_machine_key_is_read(key_path: str, tmp_path: Path) -> None:
    """Every machine key the check declares is read, at that literal path."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(plugin, {key_path: make_node(values={"EvilApp": _EVIL_COMMAND})})

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        f"HKLM\\SOFTWARE\\{key_path}\\EvilApp"
    ]


def test_hkcu_run_value_is_reported(tmp_path: Path) -> None:
    """A malicious per-user Run value fires as a USER finding naming its profile."""
    plugin = make_plugin(RunKeys, tmp_path, user_profiles=make_user_profiles("alice"))
    setup_keys(plugin, {_HKCU_RUN_KEY: make_node(values={"EvilApp": _EVIL_COMMAND})})

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"HKU\alice\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp"
    ], "the HKU branch is the only wired key, so a HKLM-only check finds nothing"
    assert findings[0].value == _EVIL_COMMAND
    assert findings[0].access_gained is AccessLevel.USER
    assert _shipped_severity(findings[0]) >= Severity.MEDIUM


def test_hkcu_onedrive_stays_quiet(tmp_path: Path) -> None:
    """The OneDrive auto-start every real profile carries stays below MEDIUM."""
    plugin = make_plugin(RunKeys, tmp_path, user_profiles=make_user_profiles("alice"))
    setup_keys(
        plugin, {_HKCU_RUN_KEY: make_node(values={"OneDrive": _ONEDRIVE_COMMAND})}
    )

    findings = plugin.run()
    resolved = replace(findings[0], exists=True, is_lolbin=False, signer="Microsoft")

    assert findings[0].access_gained is AccessLevel.USER
    assert _shipped_severity(resolved) < Severity.MEDIUM, (
        "the shipped OneDrive auto-start rule must suppress it under HKU too"
    )


def test_runonceex_section_command_is_reported(tmp_path: Path) -> None:
    """A command in a RunOnceEx section subkey fires, where the real layout puts it."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(plugin, {_HKLM_RUNONCEEX_KEY: _section_node({"1": _SECTION_COMMAND})})

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\1"
    ], "RunOnceEx commands live one level down, in an ordered section subkey"
    assert findings[0].value == _SECTION_COMMAND
    assert findings[0].access_gained is AccessLevel.SYSTEM
    assert _shipped_severity(findings[0]) >= Severity.MEDIUM


def test_runonceex_depend_dll_is_reported(tmp_path: Path) -> None:
    """The Depend subkey a section loads DLLs from is descended into as well."""
    plugin = make_plugin(RunKeys, tmp_path)
    depend = make_node(name="Depend", values={"1": _SECTION_DEPEND_DLL})
    section = make_node(
        name="0001", values={"1": _SECTION_COMMAND}, children={"Depend": depend}
    )
    setup_keys(plugin, {_HKLM_RUNONCEEX_KEY: make_node(children={"0001": section})})

    findings = plugin.run()

    assert sorted(finding.path for finding in findings) == [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\1",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend\1",
    ]


def test_runex_section_command_is_reported(tmp_path: Path) -> None:
    """RunEx uses the same section layout and is descended into the same way."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(plugin, {_HKLM_RUNEX_KEY: _section_node({"1": _SECTION_COMMAND})})

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx\0001\1"
    ]


def test_wow6432node_runonceex_section_command_is_reported(tmp_path: Path) -> None:
    """The 32-bit RunOnceEx a WoW64 dropper writes to is descended into too."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(
        plugin, {_HKLM_WOW64_RUNONCEEX_KEY: _section_node({"1": _SECTION_COMMAND})}
    )

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion"
        r"\RunOnceEx\0001\1"
    ]


def test_hkcu_runonceex_section_command_is_reported(tmp_path: Path) -> None:
    """A per-user RunOnceEx section fires as a USER finding naming its profile."""
    plugin = make_plugin(RunKeys, tmp_path, user_profiles=make_user_profiles("alice"))
    setup_keys(plugin, {_HKCU_RUNONCEEX_KEY: _section_node({"1": _SECTION_COMMAND})})

    findings = plugin.run()

    assert [finding.path for finding in findings] == [
        r"HKU\alice\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\1"
    ]
    assert findings[0].access_gained is AccessLevel.USER


def test_section_caption_stays_quiet(tmp_path: Path) -> None:
    """A section carrying only its progress caption reports nothing at all."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(
        plugin, {_HKLM_RUNONCEEX_KEY: _section_node({"(Default)": _SECTION_CAPTION})}
    )

    assert plugin.run() == [], (
        "the unnamed default of a section is the progress caption, never executed, "
        "so reporting it would flag every installer-written RunOnceEx section"
    )


def test_shipped_allow_rule_covers_a_section_command(tmp_path: Path) -> None:
    """A benign signed installer command in a section is suppressed as elsewhere."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(
        plugin, {_HKLM_RUNONCEEX_KEY: _section_node({"1": _EDGE_WEBVIEW_COMMAND})}
    )

    findings = plugin.run()
    resolved = replace(findings[0], exists=True, is_lolbin=False, signer="Microsoft")

    assert _shipped_severity(resolved) < Severity.MEDIUM, (
        "section findings carry the run_keys check id, so the shipped allow rules "
        "must keep a signed installer command below the reporting threshold"
    )


def test_flat_run_key_subkeys_are_not_descended(tmp_path: Path) -> None:
    """Run and RunOnce execute their own values only, so their subkeys stay quiet."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_keys(plugin, {_HKLM_RUN_KEY: _section_node({"1": _SECTION_COMMAND})})

    assert plugin.run() == [], (
        "Windows never executes a subkey of Run, so descending there would invent "
        "findings the operating system would not act on"
    )


def test_setup_hklm_refuses_a_new_path_blind_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A module outside the frozen allowlist cannot wire a blanket hive by accident."""
    plugin = make_plugin(RunKeys, tmp_path)
    monkeypatch.setitem(globals(), "__file__", "tests/plugins/test_brand_new_check.py")

    with pytest.raises(AssertionError, match="key_path"):
        setup_hklm(plugin, make_node(values={"EvilApp": "evil.exe"}))


def test_setup_hklm_key_path_binds_the_read(tmp_path: Path) -> None:
    """A key_path answers that path only, so a check reading elsewhere finds nothing."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_hklm(plugin, make_node(values={"EvilApp": "evil.exe"}), key_path=_DECOY_KEY)

    assert plugin.run() == []


def test_setup_hklm_still_serves_a_frozen_caller(tmp_path: Path) -> None:
    """The path-blind form keeps working for the modules frozen into the allowlist."""
    plugin = make_plugin(RunKeys, tmp_path)
    setup_hklm(
        plugin, make_node(values={"EvilApp": "evil.exe"}), hive_path=_SOFTWARE_HIVE
    )

    assert plugin.run(), "the frozen path-blind wiring must keep serving its callers"
