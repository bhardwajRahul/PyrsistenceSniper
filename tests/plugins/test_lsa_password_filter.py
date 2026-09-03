"""Tests for the LsaPasswordFilter declarative plugin (T1556.002)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel, Finding, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.resolver import ResolutionPipeline
from pyrsistencesniper.plugins.T1556.lsa_password_filter import LsaPasswordFilter

from .conftest import make_node, make_plugin, setup_filesystem, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_LSA_KEY = r"ControlSet001\Control\Lsa"
_LSA_PATH = r"HKLM\SYSTEM\ControlSet001\Control\Lsa\Notification Packages"


def _lsa_plugin(tmp_path: Path, packages: object) -> LsaPasswordFilter:
    """Build the plugin with the Lsa key holding the given Notification Packages."""
    plugin = make_plugin(LsaPasswordFilter, tmp_path)
    setup_keys(
        plugin, {_LSA_KEY: make_node(values={"Notification Packages": packages})}
    )
    return plugin


def _classify(finding: Finding) -> Severity:
    """Classify a finding with the shipped profile, as a real scan would."""
    return (
        DetectionProfile.load(None).policy_for("lsa_password_filter").classify(finding)
    )


def test_non_default_notification_package_is_reported(tmp_path: Path) -> None:
    """A package beyond the Windows default produces a finding at the Lsa key."""
    plugin = _lsa_plugin(tmp_path, ["scecli", "evilfltr"])

    findings = plugin.run()

    assert len(findings) == 2, "Expected one finding per notification package"
    assert [finding.value for finding in findings] == ["scecli", "evilfltr"]
    assert findings[1].path == _LSA_PATH, (
        "Finding must name the Lsa key it was read from"
    )
    assert findings[1].access_gained is AccessLevel.SYSTEM


def test_bare_package_name_resolves_to_its_system32_dll(tmp_path: Path) -> None:
    """The DLL behind a suffix-less package name is existence- and hash-checked."""
    plugin = _lsa_plugin(tmp_path, "evilfltr")
    setup_filesystem(plugin, {r"Windows\System32\evilfltr.dll": b"MZ payload"})

    finding = plugin.run()[0]
    resolved = ResolutionPipeline(plugin.filesystem).resolve(finding)

    assert finding.resolve_target == r"Windows\System32\evilfltr.dll"
    assert resolved.exists is True, "The password filter DLL must be looked for on disk"
    assert resolved.sha256, "A password filter DLL that exists must be hashed"


def test_missing_package_dll_is_reported_as_absent(tmp_path: Path) -> None:
    """A package naming no DLL on disk resolves to absent, not to unknown."""
    plugin = _lsa_plugin(tmp_path, "evilfltr")

    resolved = ResolutionPipeline(plugin.filesystem).resolve(plugin.run()[0])

    assert resolved.exists is False, "An absent filter DLL must report absence"


def test_default_package_stays_quiet(tmp_path: Path) -> None:
    """Resolving scecli leaves the shipped allow rule matching, so it stays quiet."""
    plugin = _lsa_plugin(tmp_path, "scecli")
    setup_filesystem(plugin, {r"Windows\System32\scecli.dll": b"MZ default"})

    resolved = ResolutionPipeline(plugin.filesystem).resolve(plugin.run()[0])

    assert resolved.value == "scecli", "Resolution must not rewrite the reported value"
    assert _classify(resolved) < Severity.MEDIUM, (
        "The Windows default must not be reported"
    )


def test_package_carrying_a_path_keeps_the_default_resolution(tmp_path: Path) -> None:
    """A value that already looks like a path is left for the resolver to handle."""
    plugin = _lsa_plugin(tmp_path, r"C:\ProgramData\evilfltr.dll")

    assert plugin.run()[0].resolve_target == ""
