"""Tests for RidHijacking and RidSuborner binary-parsing plugins (T1098)."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1098.rid_hijacking import RidHijacking, RidSuborner

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def _f_value(relative_id: int) -> bytes:
    """Build a SAM F value carrying the given RID at offset 0x30."""
    return b"\x00" * 0x30 + struct.pack("<I", relative_id) + b"\x00" * 20


def _sam_plugin(
    plugin_cls: type, tmp_path: Path, accounts: dict[str, dict[str, object]]
) -> object:
    """Build the plugin over a SAM Users key holding the given account subkeys."""
    children = {
        subkey_name: make_node(name=subkey_name, values=values)
        for subkey_name, values in accounts.items()
    }
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, make_node(children=children), hive_path="/fake/SAM")
    return plugin


class TestRidHijacking:
    """Cases for an account whose F value RID disagrees with its subkey name."""

    def test_detects_rid_mismatch(self, tmp_path: Path) -> None:
        """A subkey named 0x3E9 whose F value claims RID 500 is an admin in disguise."""
        plugin = _sam_plugin(RidHijacking, tmp_path, {"000003E9": {"F": _f_value(500)}})

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert "mismatch" in finding.value.lower()
        assert "0x3E9" in finding.value
        assert "500" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1098" in finding.mitre_id
        assert "SAM" in finding.path

    def test_matching_rid_returns_empty(self, tmp_path: Path) -> None:
        """Every untampered account agrees with its own subkey name."""
        plugin = _sam_plugin(RidHijacking, tmp_path, {"000001F4": {"F": _f_value(500)}})

        assert plugin.run() == []

    def test_f_value_too_short(self, tmp_path: Path) -> None:
        """An F value shorter than 52 bytes holds no RID field to compare."""
        plugin = _sam_plugin(RidHijacking, tmp_path, {"000003E9": {"F": b"\x00" * 20}})

        assert plugin.run() == []

    def test_names_subkey_skipped(self, tmp_path: Path) -> None:
        """The Names subkey is an index, not an account, and has no RID to parse."""
        plugin = _sam_plugin(
            RidHijacking,
            tmp_path,
            {"Names": {}, "000003E9": {"F": _f_value(500)}},
        )

        assert len(plugin.run()) == 1

    def test_missing_f_value_skipped(self, tmp_path: Path) -> None:
        """A subkey with no F value records no RID, so there is nothing to compare."""
        plugin = _sam_plugin(RidHijacking, tmp_path, {"000003E9": {}})

        assert plugin.run() == []


class TestRidSuborner:
    """Cases for an ordinary account whose F value grants it the admin RID."""

    def test_detects_suborner_account(self, tmp_path: Path) -> None:
        """A non-admin subkey whose F value reads 500 logs on as the Administrator."""
        plugin = _sam_plugin(RidSuborner, tmp_path, {"000003E9": {"F": _f_value(500)}})

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert "suborner" in finding.value.lower()
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1098" in finding.mitre_id

    def test_actual_admin_not_flagged(self, tmp_path: Path) -> None:
        """The real Administrator is subkey 0x1F4 with RID 500 and must stay quiet."""
        plugin = _sam_plugin(RidSuborner, tmp_path, {"000001F4": {"F": _f_value(500)}})

        assert plugin.run() == []

    def test_non_admin_f_rid_not_flagged(self, tmp_path: Path) -> None:
        """Only RID 500 grants administrator, so a mismatch to 1001 is not suborning."""
        plugin = _sam_plugin(RidSuborner, tmp_path, {"000003E9": {"F": _f_value(1001)}})

        assert plugin.run() == []

    def test_f_value_too_short(self, tmp_path: Path) -> None:
        """An F value shorter than 52 bytes holds no RID field to read."""
        plugin = _sam_plugin(RidSuborner, tmp_path, {"000003E9": {"F": b"\x00" * 10}})

        assert plugin.run() == []
