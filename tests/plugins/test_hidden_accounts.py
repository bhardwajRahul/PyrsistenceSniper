"""Tests for the hidden local account check (T1564.002)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1564.hidden_accounts import HiddenLocalAccount

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_USER_LIST_KEY = (
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
)
_USER_LIST_PATH = (
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    r"\SpecialAccounts\UserList"
)


def _user_list_plugin(tmp_path: Path, entries: dict[str, int]) -> HiddenLocalAccount:
    """Build the plugin with the UserList key holding the given entries."""
    plugin = make_plugin(HiddenLocalAccount, tmp_path)
    setup_keys(plugin, {_USER_LIST_KEY: make_node(name="UserList", values=entries)})
    return plugin


def test_account_hidden_from_the_sign_in_screen_is_reported(tmp_path: Path) -> None:
    """A UserList entry set to zero hides the account and is reported."""
    plugin = _user_list_plugin(tmp_path, {"backdoor": 0})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == rf"{_USER_LIST_PATH}\backdoor"
    assert "hidden from the sign-in screen" in findings[0].value
    assert findings[0].access_gained is AccessLevel.SYSTEM


def test_account_left_visible_stays_quiet(tmp_path: Path) -> None:
    """A UserList entry set to one keeps the account visible, so it is not hiding."""
    plugin = _user_list_plugin(tmp_path, {"Administrator": 1})

    assert plugin.run() == []


def test_only_the_hidden_entries_are_reported(tmp_path: Path) -> None:
    """A key holding both settings reports the hidden account and nothing else."""
    plugin = _user_list_plugin(tmp_path, {"Administrator": 1, "backdoor": 0})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value.startswith("backdoor")


def test_absent_user_list_reports_nothing(tmp_path: Path) -> None:
    """A host that never created the UserList key produces no finding."""
    plugin = make_plugin(HiddenLocalAccount, tmp_path)
    setup_keys(plugin, {})

    assert plugin.run() == []
