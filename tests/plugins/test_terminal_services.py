"""Tests for the Terminal Services and RDP persistence plugins (T1547.001)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.terminal_services import (
    RdpClxDll,
    RdpVirtualChannel,
    RdpWdsStartupPrograms,
    TsInitialProgram,
)

from .conftest import make_node, make_plugin, setup_hklm, setup_keys

_DECLARATIVE_CASES: list[tuple[type, str, str, str]] = [
    (TsInitialProgram, "InitialProgram", r"C:\backdoor.exe", "/fake/SOFTWARE"),
    (RdpWdsStartupPrograms, "StartupPrograms", "evil_clip", "/fake/SYSTEM"),
    (RdpClxDll, "ClxDllPath", r"C:\evil\clx.dll", "/fake/SYSTEM"),
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
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)
    assert all("T1547.001" in finding.mitre_id for finding in findings)


class TestRdpVirtualChannel:
    """Cases for RDP channel add-ins, each naming a DLL loaded into the session."""

    def test_virtual_channel_dll_detected(self, tmp_path: Path) -> None:
        """A channel add-in DLL is loaded into the SYSTEM-side session host."""
        addin_node = make_node(name="MyAddin", values={"Name": r"C:\vc.dll"})
        tree = make_node(children={"MyAddin": addin_node})

        plugin = make_plugin(RdpVirtualChannel, tmp_path)
        setup_hklm(plugin, tree)

        findings = plugin.run()
        assert len(findings) == 1
        assert r"C:\vc.dll" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_empty_addin_value_skipped(self, tmp_path: Path) -> None:
        """An addin with no DLL name loads nothing, so it is not a finding."""
        addin_node = make_node(name="EmptyAddin", values={"Name": ""})
        tree = make_node(children={"EmptyAddin": addin_node})

        plugin = make_plugin(RdpVirtualChannel, tmp_path)
        setup_hklm(plugin, tree)

        assert plugin.run() == []


_TS_RUNONCEEX_KEY = (
    r"Microsoft\Windows NT\CurrentVersion\Terminal Server\Install"
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
)
_TS_RUN_KEY = (
    r"Microsoft\Windows NT\CurrentVersion\Terminal Server\Install"
    r"\Software\Microsoft\Windows\CurrentVersion\Run"
)
_TS_RUNONCEEX_REPORTED = (
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install"
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
)


class TestTerminalServerInstallShadow:
    """Cases for the Terminal Server Install shadow of the machine Run keys."""

    def test_runonceex_section_command_detected(self, tmp_path: Path) -> None:
        """RunOnceEx keeps its commands one level down, in ordered section subkeys."""
        section = make_node(
            name="0001", values={"1": r"C:\ProgramData\evil.dll|Install"}
        )
        plugin = make_plugin(TsInitialProgram, tmp_path)
        setup_keys(plugin, {_TS_RUNONCEEX_KEY: make_node(children={"0001": section})})

        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == r"C:\ProgramData\evil.dll|Install"
        assert findings[0].path == _TS_RUNONCEEX_REPORTED + r"\0001\1"
        assert findings[0].access_gained == AccessLevel.SYSTEM

    def test_runonceex_depend_subkey_command_detected(self, tmp_path: Path) -> None:
        """A section's Depend subkey names DLLs loaded before the command runs."""
        depend = make_node(name="Depend", values={"1": r"C:\ProgramData\evil.dll"})
        section = make_node(name="0001", children={"Depend": depend})
        plugin = make_plugin(TsInitialProgram, tmp_path)
        setup_keys(plugin, {_TS_RUNONCEEX_KEY: make_node(children={"0001": section})})

        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == _TS_RUNONCEEX_REPORTED + r"\0001\Depend\1"

    def test_runonceex_section_caption_stays_quiet(self, tmp_path: Path) -> None:
        """A section's unnamed default holds the progress caption, not a command."""
        section = make_node(name="0001", values={"(Default)": "Installing updates"})
        plugin = make_plugin(TsInitialProgram, tmp_path)
        setup_keys(plugin, {_TS_RUNONCEEX_KEY: make_node(children={"0001": section})})

        assert plugin.run() == []

    def test_plain_runonceex_key_is_not_the_one_read(self, tmp_path: Path) -> None:
        """The machine-wide RunOnceEx belongs to run_keys, not to this check."""
        section = make_node(
            name="0001", values={"1": r"C:\ProgramData\evil.dll|Install"}
        )
        plugin = make_plugin(TsInitialProgram, tmp_path)
        setup_keys(
            plugin,
            {
                r"Microsoft\Windows\CurrentVersion\RunOnceEx": make_node(
                    children={"0001": section}
                )
            },
        )

        assert plugin.run() == []

    def test_flat_run_shadow_still_read(self, tmp_path: Path) -> None:
        """The Run half of the shadow holds flat values and must keep firing."""
        plugin = make_plugin(TsInitialProgram, tmp_path)
        setup_keys(
            plugin, {_TS_RUN_KEY: make_node(values={"Updater": r"C:\evil\rdp.exe"})}
        )

        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == r"C:\evil\rdp.exe"
