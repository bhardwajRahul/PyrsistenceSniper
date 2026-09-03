"""Tests for the ErrorHandlerCmd custom-run plugin in T1546/error_handler_cmd.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.error_handler_cmd import ErrorHandlerCmd

from .conftest import make_plugin

if TYPE_CHECKING:
    from pathlib import Path


def test_file_present(tmp_path: Path) -> None:
    """ErrorHandler.cmd planted in System32 produces a SYSTEM finding."""
    plugin = make_plugin(ErrorHandlerCmd, tmp_path)
    system32 = tmp_path / "Windows" / "System32"
    system32.mkdir(parents=True)
    (system32 / "ErrorHandler.cmd").write_text("evil-code")
    findings = plugin.run()
    assert len(findings) == 1
    assert "ErrorHandler.cmd" in findings[0].value
    assert findings[0].check_id == "error_handler_cmd"
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_file_absent(tmp_path: Path) -> None:
    """No ErrorHandler.cmd on disk produces no findings."""
    plugin = make_plugin(ErrorHandlerCmd, tmp_path)
    assert plugin.run() == []
