"""Tests for the TelemetryController command hijack plugin (T1546)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel, Finding, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1546.telemetry_controller import TelemetryController

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_KEY = r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController"


def test_telemetry_command_found(tmp_path: Path) -> None:
    """CompatTelRunner executes a controller Command as SYSTEM."""
    child = make_node(name="EvilCtrl", values={"Command": "C:\\evil.exe"})
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(children={"EvilCtrl": child})})

    findings = plugin.run()

    assert len(findings) == 1
    assert "evil.exe" in findings[0].value
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_telemetry_maintenance_command_found(tmp_path: Path) -> None:
    """MaintenanceCommand executes the same way as Command and is reported too."""
    child = make_node(name="EvilCtrl", values={"MaintenanceCommand": "C:\\evil.exe"})
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(children={"EvilCtrl": child})})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path.endswith("MaintenanceCommand")


def test_telemetry_binary_found(tmp_path: Path) -> None:
    """Binary names the DLL CompatTelRunner loads and is reported alongside Command."""
    child = make_node(name="EvilCtrl", values={"Binary": "C:\\ProgramData\\evil.dll"})
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(children={"EvilCtrl": child})})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == "C:\\ProgramData\\evil.dll"
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        r"\AppCompatFlags\TelemetryController\EvilCtrl\Binary"
    )
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_telemetry_binary_and_command_are_both_reported(tmp_path: Path) -> None:
    """A controller carrying both a DLL and a command yields a finding for each."""
    child = make_node(
        name="EvilCtrl",
        values={"Binary": "evil.dll", "Command": "DoScheduledTelemetryRun"},
    )
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(children={"EvilCtrl": child})})

    findings = plugin.run()

    assert [finding.path.rsplit("\\", 1)[1] for finding in findings] == [
        "Binary",
        "Command",
    ]


def test_telemetry_reads_the_appcompatflags_key(tmp_path: Path) -> None:
    """The check reads the AppCompatFlags key CompatTelRunner actually executes."""
    child = make_node(name="EvilCtrl", values={"Command": "C:\\evil.exe"})
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(children={"EvilCtrl": child})})

    findings = plugin.run()

    assert findings
    assert "AppCompatFlags" in findings[0].path


def test_telemetry_ignores_the_diagtrack_key(tmp_path: Path) -> None:
    """The old DiagTrack path does not exist on Windows and must not be what is read."""
    child = make_node(name="EvilCtrl", values={"Command": "C:\\evil.exe"})
    stale = (
        r"Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TelemetryController"
    )
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {stale: make_node(children={"EvilCtrl": child})})

    assert plugin.run() == []


def test_telemetry_parent_command_found(tmp_path: Path) -> None:
    """A Command on the TelemetryController key itself is reported."""
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(values={"Command": "C:\\evil.exe"})})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path.endswith("TelemetryController\\Command")


def test_telemetry_no_command_value(tmp_path: Path) -> None:
    """A controller key with no command or binary value executes nothing."""
    child = make_node(name="SomeCtrl", values={"Other": "val"})
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(children={"SomeCtrl": child})})

    assert plugin.run() == []


def test_telemetry_bookkeeping_values_stay_quiet(tmp_path: Path) -> None:
    """Run timestamps and result codes are not payloads and produce nothing."""
    child = make_node(
        name="Appraiser", values={"LastRunTime": 134309746170445826, "Result": 0}
    )
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {_KEY: make_node(children={"Appraiser": child})})

    assert plugin.run() == []


def test_telemetry_absent_key(tmp_path: Path) -> None:
    """A host that never registered a controller has no key to read."""
    plugin = make_plugin(TelemetryController, tmp_path)
    setup_keys(plugin, {})

    assert plugin.run() == []


def test_attacker_binary_reaches_medium() -> None:
    """An unsigned DLL registered as Binary is not suppressed by the shipped profile."""
    policy = DetectionProfile.load(None).policy_for("telemetry_controller")
    finding = Finding(
        path=(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\AppCompatFlags\TelemetryController\Updater\Binary"
        ),
        value=r"C:\ProgramData\evil.dll",
        check_id="telemetry_controller",
        signer="",
        is_lolbin=False,
    )

    assert policy.classify(finding) >= Severity.MEDIUM
