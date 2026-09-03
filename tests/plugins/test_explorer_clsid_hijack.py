"""Tests for the ExplorerClsidHijack plugin in T1546/explorer_clsid_hijack.py."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.explorer_clsid_hijack import ExplorerClsidHijack

from .conftest import (
    make_node,
    make_plugin,
    make_user_profiles,
    setup_hklm,
    setup_keys,
    setup_usrclass_only,
)

_MY_COMPUTER = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
_USER_COMMAND_KEY = rf"CLSID\{_MY_COMPUTER}\shell\open\command"
_PAYLOAD = r"C:\Users\bob\AppData\Roaming\x.exe"


def test_hijacked_shell_command_detected(tmp_path: Path) -> None:
    """A hijacked (Default) shell command produces a finding per CLSID target."""
    node = make_node(values={"(Default)": r"C:\evil_clsid.exe"})
    plugin = make_plugin(ExplorerClsidHijack, tmp_path)
    setup_hklm(plugin, node, hive_path="/fake/SOFTWARE")
    findings = plugin.run()
    assert len(findings) == 3
    assert all("evil_clsid.exe" in finding.value for finding in findings)
    assert all(finding.check_id == "explorer_clsid_hijack" for finding in findings)
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)
    paths = "\n".join(finding.path for finding in findings)
    assert "{52205fd8-5dfb-447d-801a-d0b52f2e83e1}" in paths
    assert "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" in paths
    assert "{450D8FBA-AD25-11D0-98A8-0800361B1103}" in paths


class TestPerUserClsidHijack:
    """A non-admin hijack lands in UsrClass.dat, whose root is Software\\Classes."""

    def test_per_user_hijack_read_from_the_hive_root(self, tmp_path: Path) -> None:
        """The lookup drops the classes prefix the UsrClass.dat root supplies."""
        plugin = make_plugin(
            ExplorerClsidHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_keys(
            plugin, {_USER_COMMAND_KEY: make_node(values={"(Default)": _PAYLOAD})}
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\victim\SOFTWARE\Classes\CLSID"
            r"\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\open\command"
        )
        assert findings[0].value == _PAYLOAD
        assert findings[0].access_gained is AccessLevel.USER

    def test_per_user_hijack_is_read_out_of_usrclass_not_ntuser(
        self, tmp_path: Path
    ) -> None:
        """NTUSER.DAT holds no class registrations, so only UsrClass.dat may answer."""
        plugin = make_plugin(
            ExplorerClsidHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_usrclass_only(
            plugin, {_USER_COMMAND_KEY: make_node(values={"(Default)": _PAYLOAD})}
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].access_gained is AccessLevel.USER

    def test_undeclared_per_user_clsid_stays_quiet(self, tmp_path: Path) -> None:
        """A per-user shell command on a CLSID the check never declares is not read."""
        plugin = make_plugin(
            ExplorerClsidHijack, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_keys(
            plugin,
            {
                r"CLSID\{11111111-2222-3333-4444-555555555555}\shell\open\command": (
                    make_node(values={"(Default)": _PAYLOAD})
                )
            },
        )

        assert plugin.run() == []
