"""Tests for AccessibilityTools signature and PE-identity comparison."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.accessibility_tools import AccessibilityTools

from .conftest import make_plugin, setup_filesystem

_MODULE = "pyrsistencesniper.plugins.T1546.accessibility_tools"
_MICROSOFT = "Microsoft Windows"
_CATALOG_REFERENCE = r"Windows\System32\cmd.exe"
_SETHC = r"Windows\System32\sethc.exe"
_LOCK_SCREEN_TOOLS = (
    r"Windows\System32\sethc.exe",
    r"Windows\System32\osk.exe",
    r"Windows\System32\Narrator.exe",
    r"Windows\System32\Magnify.exe",
    r"Windows\System32\utilman.exe",
    r"Windows\System32\AtBroker.exe",
    r"Windows\System32\DisplaySwitch.exe",
)


class _FakeSignerExtractor:
    """Answers signer lookups from a fixed image-path to signer-name mapping."""

    def __init__(self, signers: dict[str, str]) -> None:
        self._signers = {path.casefold(): name for path, name in signers.items()}

    def extract(self, resolved_path: str) -> str:
        """Return the signer wired for a path, or empty when none was wired."""
        return self._signers.get(resolved_path.casefold(), "")


def _signature_data(
    signers: dict[str, str], original_names: dict[str, str] | None = None
) -> AbstractContextManager[Any]:
    """Replace the catalog and PE-version lookups with wired-in answers."""
    names = {name.casefold(): value for name, value in (original_names or {}).items()}
    return patch.multiple(
        _MODULE,
        SignerExtractor=lambda _filesystem: _FakeSignerExtractor(signers),
        _original_filename=lambda host_path: names.get(host_path.name.casefold(), ""),
    )


class TestAccessibilityToolsReplacement:
    """A binary that is not the original Microsoft ships is reported."""

    def test_unsigned_binary_is_reported(self, tmp_path: Path) -> None:
        """An accessibility EXE with no Microsoft signature is a replacement."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, {_SETHC: b"implant"})

        with _signature_data({_CATALOG_REFERENCE: _MICROSOFT}):
            findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == _SETHC
        assert findings[0].resolve_target == _SETHC
        assert findings[0].access_gained is AccessLevel.SYSTEM
        assert "Not the Microsoft-signed original" in findings[0].value

    def test_signed_binary_planted_under_another_name_is_reported(
        self, tmp_path: Path
    ) -> None:
        """A Microsoft-signed cmd.exe copied over sethc.exe is a replacement."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, {_SETHC: b"cmd-bytes"})
        signers = {_CATALOG_REFERENCE: _MICROSOFT, _SETHC: _MICROSOFT}

        with _signature_data(signers, {"sethc.exe": "Cmd.Exe"}):
            findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == _SETHC
        assert "Cmd.Exe" in findings[0].value

    def test_every_lock_screen_tool_is_inspected(self, tmp_path: Path) -> None:
        """All seven binaries reachable from the lock screen are checked."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, dict.fromkeys(_LOCK_SCREEN_TOOLS, b"implant"))

        with _signature_data({_CATALOG_REFERENCE: _MICROSOFT}):
            findings = plugin.run()

        assert {finding.path for finding in findings} == set(_LOCK_SCREEN_TOOLS)


class TestAccessibilityToolsBenign:
    """An untampered Windows installation produces nothing."""

    def test_signed_original_stays_quiet(self, tmp_path: Path) -> None:
        """A Microsoft-signed sethc.exe that identifies as sethc.exe is original."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, {_SETHC: b"real-sethc"})
        signers = {_CATALOG_REFERENCE: _MICROSOFT, _SETHC: _MICROSOFT}

        with _signature_data(signers, {"sethc.exe": "sethc.exe"}):
            findings = plugin.run()

        assert findings == []

    @pytest.mark.parametrize(
        ("tool_path", "original_name"),
        [
            (r"Windows\System32\utilman.exe", "utilman2.exe"),
            (r"Windows\System32\Magnify.exe", "ScreenMagnifier.exe"),
            (r"Windows\System32\Narrator.exe", "SR.exe"),
            (r"Windows\System32\AtBroker.exe", "ATBroker.exe"),
        ],
    )
    def test_shipped_internal_name_stays_quiet(
        self, tmp_path: Path, tool_path: str, original_name: str
    ) -> None:
        """Tools whose internal name differs from their file name are not findings."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, {tool_path: b"real-binary"})
        signers = {_CATALOG_REFERENCE: _MICROSOFT, tool_path: _MICROSOFT}
        file_name = Path(tool_path).name

        with _signature_data(signers, {file_name: original_name}):
            findings = plugin.run()

        assert findings == []

    def test_signed_binary_without_version_resource_stays_quiet(
        self, tmp_path: Path
    ) -> None:
        """A signed binary carrying no OriginalFilename cannot be called replaced."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, {_SETHC: b"real-sethc"})
        signers = {_CATALOG_REFERENCE: _MICROSOFT, _SETHC: _MICROSOFT}

        with _signature_data(signers):
            findings = plugin.run()

        assert findings == []

    def test_absent_tools_produce_nothing(self, tmp_path: Path) -> None:
        """A collection holding none of the tools yields no findings."""
        plugin = make_plugin(AccessibilityTools, tmp_path)

        with _signature_data({_CATALOG_REFERENCE: _MICROSOFT}):
            findings = plugin.run()

        assert findings == []


class TestAccessibilityToolsWithoutSignatureData:
    """Without the catalog store the check reports nothing rather than everything."""

    def test_catalog_less_collection_reports_nothing(self, tmp_path: Path) -> None:
        """Seven unresolvable signatures are a missing catalog, not seven backdoors."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, dict.fromkeys(_LOCK_SCREEN_TOOLS, b"real-binary"))

        with _signature_data({}):
            findings = plugin.run()

        assert findings == []

    def test_embedded_signature_alone_does_not_open_the_check(
        self, tmp_path: Path
    ) -> None:
        """kernel32.dll resolves without a catalog, so it cannot vouch for one."""
        plugin = make_plugin(AccessibilityTools, tmp_path)
        setup_filesystem(plugin, {_SETHC: b"real-sethc"})

        with _signature_data({r"Windows\System32\kernel32.dll": _MICROSOFT}):
            findings = plugin.run()

        assert findings == []
