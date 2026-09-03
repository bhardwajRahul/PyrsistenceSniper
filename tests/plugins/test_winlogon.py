"""Tests for the Winlogon logon-helper plugins (T1547.004)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pyrsistencesniper.core.models import AccessLevel, Finding, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1547.winlogon import (
    WinlogonAppSetup,
    WinlogonGinaDll,
    WinlogonMPNotify,
    WinlogonNotifyPackages,
    WinlogonShell,
    WinlogonSystem,
    WinlogonTaskman,
    WinlogonUserinit,
    WinlogonVMApplet,
)
from pyrsistencesniper.plugins.T1556.lsa_password_filter import LsaPasswordFilter

from .conftest import make_node, make_plugin, make_user_profiles, setup_keys

_MACHINE_KEY = r"Microsoft\Windows NT\CurrentVersion\Winlogon"
_USER_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_MACHINE_PATH = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
_NOTIFY_KEY = r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
_NOTIFY_PATH = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
_LSA_KEY = r"ControlSet001\Control\Lsa"
_DECOY_KEY = r"Decoy\Path\No\Winlogon\Check\Declares"

_DEFAULT_USERINIT = r"C:\Windows\system32\userinit.exe"
_PAYLOAD = r"C:\ProgramData\evil.exe"

_VALUE_CHECKS: list[tuple[type, str, str]] = [
    (WinlogonShell, "Shell", r"C:\evil\shell.exe"),
    (WinlogonUserinit, "Userinit", r"C:\evil\init.exe"),
    (WinlogonMPNotify, "mpnotify", r"C:\evil\notify.dll"),
    (WinlogonAppSetup, "AppSetup", r"C:\evil\appsetup.exe"),
    (WinlogonSystem, "System", r"C:\evil\system.exe"),
    (WinlogonTaskman, "Taskman", r"C:\evil\taskman.exe"),
    (WinlogonVMApplet, "VMApplet", r"C:\evil\vmapplet.exe"),
    (WinlogonGinaDll, "GinaDLL", r"C:\evil\gina.dll"),
]

_VALUE_CHECK_IDS = [value_name for _cls, value_name, _data in _VALUE_CHECKS]

_BENIGN_DEFAULTS: list[tuple[type, str, str]] = [
    (WinlogonShell, "Shell", "explorer.exe"),
    (WinlogonVMApplet, "VMApplet", "SystemPropertiesPerformance.exe /pagefile"),
]


def _classify(check_id: str, value: str, *, signer: str) -> Severity:
    """Classify one value through the shipped profile exactly as a scan would."""
    finding = Finding(
        path=f"{_MACHINE_PATH}\\Userinit",
        value=value,
        check_id=check_id,
        access_gained=AccessLevel.SYSTEM,
        signer=signer,
        exists=bool(signer),
    )
    return DetectionProfile.load(None).policy_for(check_id).classify(finding)


@pytest.mark.parametrize(
    ("plugin_cls", "value_name", "value_data"), _VALUE_CHECKS, ids=_VALUE_CHECK_IDS
)
def test_value_is_read_from_the_winlogon_key(
    tmp_path: Path, plugin_cls: type, value_name: str, value_data: str
) -> None:
    """Each Winlogon value check reads the machine Winlogon key and reports it."""
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_keys(plugin, {_MACHINE_KEY: make_node(values={value_name: value_data})})

    findings = plugin.run()

    assert [(finding.path, finding.value) for finding in findings] == [
        (f"{_MACHINE_PATH}\\{value_name}", value_data)
    ]
    assert findings[0].access_gained is AccessLevel.SYSTEM
    assert findings[0].mitre_id == "T1547.004"


@pytest.mark.parametrize(
    ("plugin_cls", "value_name", "value_data"), _VALUE_CHECKS, ids=_VALUE_CHECK_IDS
)
def test_undeclared_key_produces_nothing(
    tmp_path: Path, plugin_cls: type, value_name: str, value_data: str
) -> None:
    """A hive answering only an undeclared key yields nothing, pinning the read."""
    plugin = make_plugin(plugin_cls, tmp_path, user_profiles=make_user_profiles())
    setup_keys(plugin, {_DECOY_KEY: make_node(values={value_name: value_data})})

    assert plugin.run() == []


@pytest.mark.parametrize(
    ("plugin_cls", "value_name", "value_data"),
    _BENIGN_DEFAULTS,
    ids=["Shell", "VMApplet"],
)
def test_benign_default_is_still_emitted_by_run(
    tmp_path: Path, plugin_cls: type, value_name: str, value_data: str
) -> None:
    """Known-good defaults are suppressed by the profile, never inside run()."""
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_keys(plugin, {_MACHINE_KEY: make_node(values={value_name: value_data})})

    findings = plugin.run()

    assert [finding.value for finding in findings] == [value_data]


def test_userinit_appended_payload_becomes_its_own_finding(tmp_path: Path) -> None:
    """The command appended after the comma must resolve on its own merits."""
    plugin = make_plugin(WinlogonUserinit, tmp_path)
    setup_keys(
        plugin,
        {
            _MACHINE_KEY: make_node(
                values={"Userinit": f"{_DEFAULT_USERINIT},{_PAYLOAD}"}
            )
        },
    )

    findings = plugin.run()

    assert [finding.value for finding in findings] == [_DEFAULT_USERINIT, _PAYLOAD]
    assert {finding.path for finding in findings} == {f"{_MACHINE_PATH}\\Userinit"}


def test_userinit_never_emits_an_unsplit_comma_blob(tmp_path: Path) -> None:
    """A payload hidden inside one blob resolves as neither command and is missed."""
    plugin = make_plugin(WinlogonUserinit, tmp_path)
    setup_keys(
        plugin,
        {
            _MACHINE_KEY: make_node(
                values={"Userinit": f"{_DEFAULT_USERINIT},{_PAYLOAD},"}
            )
        },
    )

    findings = plugin.run()

    assert all("," not in finding.value for finding in findings)


def test_userinit_default_loses_its_trailing_comma(tmp_path: Path) -> None:
    """The shipped default ends in a comma, which stops the file resolving at all."""
    plugin = make_plugin(WinlogonUserinit, tmp_path)
    setup_keys(
        plugin,
        {_MACHINE_KEY: make_node(values={"Userinit": f"{_DEFAULT_USERINIT},"})},
    )

    findings = plugin.run()

    assert [finding.value for finding in findings] == [_DEFAULT_USERINIT]


def test_userinit_splits_the_per_user_value_too(tmp_path: Path) -> None:
    """The HKU half of the Userinit target splits its components the same way."""
    plugin = make_plugin(
        WinlogonUserinit, tmp_path, user_profiles=make_user_profiles("alice")
    )
    setup_keys(
        plugin,
        {_USER_KEY: make_node(values={"Userinit": f"{_DEFAULT_USERINIT},{_PAYLOAD}"})},
    )

    findings = plugin.run()

    assert [finding.value for finding in findings] == [_DEFAULT_USERINIT, _PAYLOAD]
    assert {finding.path for finding in findings} == {
        r"HKU\alice\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
    }
    assert all(finding.access_gained is AccessLevel.USER for finding in findings)


@pytest.mark.parametrize(
    ("plugin_cls", "value_name"),
    [(WinlogonAppSetup, "AppSetup"), (WinlogonSystem, "System")],
    ids=["AppSetup", "System"],
)
def test_comma_delimited_lists_are_split(
    tmp_path: Path, plugin_cls: type, value_name: str
) -> None:
    """AppSetup and System are comma-delimited lists Winlogon runs entry by entry."""
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_keys(
        plugin,
        {
            _MACHINE_KEY: make_node(
                values={value_name: f"C:\\Windows\\system32\\good.exe,{_PAYLOAD}"}
            )
        },
    )

    findings = plugin.run()

    assert [finding.value for finding in findings] == [
        r"C:\Windows\system32\good.exe",
        _PAYLOAD,
    ]


def test_shipped_profile_reports_the_appended_userinit_payload() -> None:
    """The split component an attacker added must reach the default report threshold."""
    assert _classify("winlogon_userinit", _PAYLOAD, signer="") >= Severity.MEDIUM


def test_shipped_profile_stays_quiet_on_the_default_userinit() -> None:
    """The legitimate userinit.exe component must not be reported."""
    severity = _classify(
        "winlogon_userinit", _DEFAULT_USERINIT, signer="Microsoft Windows"
    )

    assert severity < Severity.MEDIUM


def test_notify_reads_the_dll_name_of_every_notify_subkey(tmp_path: Path) -> None:
    """Winlogon loads the DllName of each Notify subkey into its own SYSTEM process."""
    plugin = make_plugin(WinlogonNotifyPackages, tmp_path)
    setup_keys(
        plugin,
        {
            _NOTIFY_KEY: make_node(
                children={
                    "evilnotify": make_node(
                        name="evilnotify",
                        values={"DllName": r"C:\ProgramData\evil.dll"},
                    )
                }
            )
        },
    )

    findings = plugin.run()

    assert [(finding.path, finding.value) for finding in findings] == [
        (f"{_NOTIFY_PATH}\\evilnotify\\DllName", r"C:\ProgramData\evil.dll")
    ]
    assert findings[0].access_gained is AccessLevel.SYSTEM


def test_notify_no_longer_reads_the_lsa_key(tmp_path: Path) -> None:
    """The LSA notification packages belong to lsa_password_filter, not to Winlogon."""
    plugin = make_plugin(WinlogonNotifyPackages, tmp_path)
    setup_keys(
        plugin,
        {
            _LSA_KEY: make_node(
                values={"Notification Packages": ["scecli", "evilfilter"]}
            )
        },
    )

    assert plugin.run() == []


def test_lsa_password_filter_still_covers_the_lsa_key(tmp_path: Path) -> None:
    """No coverage is lost by repointing Winlogon Notify away from the LSA key."""
    plugin = make_plugin(LsaPasswordFilter, tmp_path)
    setup_keys(
        plugin,
        {
            _LSA_KEY: make_node(
                values={"Notification Packages": ["scecli", "evilfilter"]}
            )
        },
    )

    findings = plugin.run()

    assert [finding.value for finding in findings] == ["scecli", "evilfilter"]
    assert all(finding.mitre_id == "T1556.002" for finding in findings)
