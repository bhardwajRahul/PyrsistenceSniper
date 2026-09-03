"""Tests for the Administrators group membership check (T1098)."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1098.local_admin_accounts import (
    AdministratorsGroupMembership,
)

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_USER_LIST_KEY = (
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
)
_ADMINISTRATORS_KEY = r"SAM\Domains\Builtin\Aliases\00000220"
_ACCOUNT_KEY = r"SAM\Domains\Account"
_USERS_KEY = r"SAM\Domains\Account\Users"
_LOCAL_ALIASES_KEY = r"SAM\Domains\Account\Aliases"
_MACHINE_SID = "S-1-5-21-111-222-333"

_ALIAS_HEADER_SIZE = 0x34
_V_HEADER_SIZE = 0xCC


def _sid_bytes(*subauthorities: int) -> bytes:
    """Build the binary SID the SAM stores for an S-1-5 identifier."""
    return (
        bytes([1, len(subauthorities)])
        + (5).to_bytes(6, "big")
        + b"".join(struct.pack("<I", subauthority) for subauthority in subauthorities)
    )


def _machine_sid_bytes(relative_id: int | None = None) -> bytes:
    """Build a SID in this machine's own domain, optionally naming one account."""
    if relative_id is None:
        return _sid_bytes(21, 111, 222, 333)
    return _sid_bytes(21, 111, 222, 333, relative_id)


def _alias_value(*member_sids: bytes) -> bytes:
    """Build an alias C value whose member list holds the given SIDs."""
    members = b"".join(member_sids)
    header = bytearray(_ALIAS_HEADER_SIZE)
    struct.pack_into("<I", header, 0x28, 0)
    struct.pack_into("<I", header, 0x2C, len(members))
    struct.pack_into("<I", header, 0x30, len(member_sids))
    return bytes(header) + members


def _user_value(account_name: str) -> bytes:
    """Build a SAM user V value carrying the given account name."""
    encoded = account_name.encode("utf-16-le")
    header = bytearray(_V_HEADER_SIZE)
    struct.pack_into("<I", header, 0x0C, 0)
    struct.pack_into("<I", header, 0x10, len(encoded))
    return bytes(header) + encoded


def _account_value() -> bytes:
    """Build the Account V value, which ends with the machine's own domain SID."""
    return bytes(40) + _machine_sid_bytes()


def _users_node(accounts: dict[int, str]) -> object:
    """Build the SAM Users key holding one subkey per account, named by RID."""
    children = {
        f"{relative_id:08X}": make_node(
            name=f"{relative_id:08X}", values={"V": _user_value(account_name)}
        )
        for relative_id, account_name in accounts.items()
    }
    children["Names"] = make_node(name="Names")
    return make_node(name="Users", children=children)


def _membership_keys(
    members: tuple[bytes, ...],
    accounts: dict[int, str],
    *,
    hidden: dict[str, int] | None = None,
    group_ids: tuple[int, ...] = (),
) -> dict[str, object]:
    """Wire the SAM and SOFTWARE keys the Administrators membership check reads."""
    keys: dict[str, object] = {
        _ADMINISTRATORS_KEY: make_node(values={"C": _alias_value(*members)}),
        _ACCOUNT_KEY: make_node(values={"V": _account_value()}),
        _USERS_KEY: _users_node(accounts),
    }
    if group_ids:
        keys[_LOCAL_ALIASES_KEY] = make_node(
            children={
                f"{group_id:08X}": make_node(name=f"{group_id:08X}")
                for group_id in group_ids
            }
        )
    if hidden:
        keys[_USER_LIST_KEY] = make_node(name="UserList", values=dict(hidden))
    return keys


def test_hidden_administrator_is_reported(tmp_path: Path) -> None:
    """An Administrators member the host hides from the sign-in screen is reported."""
    plugin = make_plugin(AdministratorsGroupMembership, tmp_path)
    setup_keys(
        plugin,
        _membership_keys(
            (_machine_sid_bytes(500), _machine_sid_bytes(1001)),
            {500: "Administrator", 1001: "backdoor"},
            hidden={"backdoor": 0},
        ),
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == r"HKLM\SAM\Domains\Builtin\Aliases\00000220\C"
    assert f"backdoor ({_MACHINE_SID}-1001)" in findings[0].value
    assert findings[0].access_gained is AccessLevel.SYSTEM


def test_ordinary_administrators_stay_quiet(tmp_path: Path) -> None:
    """Members that are visible local accounts are legitimate and are not reported."""
    plugin = make_plugin(AdministratorsGroupMembership, tmp_path)
    setup_keys(
        plugin,
        _membership_keys(
            (_machine_sid_bytes(500), _machine_sid_bytes(1001)),
            {500: "Administrator", 1001: "operator"},
        ),
    )

    assert plugin.run() == []


def test_member_naming_no_account_is_reported(tmp_path: Path) -> None:
    """A local SID in Administrators that names nothing in the SAM is reported."""
    plugin = make_plugin(AdministratorsGroupMembership, tmp_path)
    setup_keys(
        plugin,
        _membership_keys(
            (_machine_sid_bytes(500), _machine_sid_bytes(4242)),
            {500: "Administrator"},
        ),
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert f"{_MACHINE_SID}-4242" in findings[0].value
    assert "names no account or group" in findings[0].value


def test_nested_local_group_stays_quiet(tmp_path: Path) -> None:
    """A local group nested in Administrators is ordinary and is not reported."""
    plugin = make_plugin(AdministratorsGroupMembership, tmp_path)
    setup_keys(
        plugin,
        _membership_keys(
            (_machine_sid_bytes(1002),),
            {500: "Administrator"},
            group_ids=(1002,),
        ),
    )

    assert plugin.run() == []


def test_member_from_another_domain_is_not_evaluated(tmp_path: Path) -> None:
    """A SID outside the machine's own domain is a domain principal, not a local one."""
    plugin = make_plugin(AdministratorsGroupMembership, tmp_path)
    setup_keys(
        plugin,
        _membership_keys(
            (_sid_bytes(21, 999, 888, 777, 512),),
            {500: "Administrator"},
        ),
    )

    assert plugin.run() == []


def test_absent_sam_reports_nothing(tmp_path: Path) -> None:
    """An image without a SAM hive produces no membership finding."""
    plugin = make_plugin(AdministratorsGroupMembership, tmp_path)
    setup_keys(plugin, {})

    assert plugin.run() == []
