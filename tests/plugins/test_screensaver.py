"""Tests for SCRNSAVE.EXE screensaver hijack detection (T1546.002)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1546.screensaver import Screensaver

from .conftest import make_node, make_plugin


def _profiles() -> list[UserProfile]:
    """Return one profile whose NTUSER.DAT is the only hive the scan can reach."""
    return [
        UserProfile(
            username="user1",
            profile_path=Path("/Users/user1"),
            ntuser_path=Path("/Users/user1/NTUSER.DAT"),
        ),
    ]


def _plugin_with_screensaver(tmp_path: Path, scrnsave_exe: str) -> Screensaver:
    """Build the plugin over a user hive whose Desktop key holds SCRNSAVE.EXE."""
    plugin = make_plugin(Screensaver, tmp_path, user_profiles=_profiles())
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = make_node(
        values={"SCRNSAVE.EXE": scrnsave_exe}
    )
    return plugin


def test_screensaver_found(tmp_path: Path) -> None:
    """The screensaver runs in the logged-on user's session, so access is USER."""
    findings = _plugin_with_screensaver(tmp_path, r"C:\evil.scr").run()

    assert len(findings) == 1
    assert "evil.scr" in findings[0].value
    assert findings[0].access_gained == AccessLevel.USER


def test_screensaver_empty_value(tmp_path: Path) -> None:
    """A blank SCRNSAVE.EXE names no executable, so there is nothing to report."""
    assert _plugin_with_screensaver(tmp_path, "  ").run() == []
