"""Tests for the LogonScripts declarative plugin (T1037.001)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import UserProfile
from pyrsistencesniper.plugins.T1037.logon_scripts import LogonScripts

from .conftest import make_node, make_plugin


def test_logon_scripts_happy_path(tmp_path: Path) -> None:
    """UserInitMprLogonScript runs at logon in the owning user's context."""
    profiles = [
        UserProfile(
            "victim",
            tmp_path / "Users" / "victim",
            tmp_path / "Users" / "victim" / "NTUSER.DAT",
        ),
    ]
    plugin = make_plugin(LogonScripts, tmp_path, user_profiles=profiles)
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = make_node(
        values={"UserInitMprLogonScript": "evil.bat"}
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == "evil.bat"
    assert findings[0].path.startswith("HKU\\victim")
