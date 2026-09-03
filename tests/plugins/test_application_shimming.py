"""Tests for the Application Shimming plugins (T1546.011)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.application_shimming import (
    CustomShimmedExecutables,
    InstalledShimDatabase,
)

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_APPCOMPAT = r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
_INSTALLED = rf"{_APPCOMPAT}\InstalledSDB"
_CUSTOM = rf"{_APPCOMPAT}\Custom"
_GUID = "{22221111-1111-1111-1111-111111111111}"


def test_installed_sdb_reports_the_database_path(tmp_path: Path) -> None:
    """A registered custom database is reported by the path it was installed to."""
    entry = make_node(
        name=_GUID,
        values={"DatabasePath": rf"C:\Windows\AppPatch\CustomSDB\{_GUID}.sdb"},
    )
    plugin = make_plugin(InstalledShimDatabase, tmp_path)
    setup_keys(plugin, {_INSTALLED: make_node(children={_GUID: entry})})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value.endswith(".sdb")
    assert findings[0].access_gained is AccessLevel.SYSTEM


def test_installed_sdb_reads_the_appcompatflags_key(tmp_path: Path) -> None:
    """The check reads InstalledSDB, the key that registers a custom database."""
    entry = make_node(name=_GUID, values={"DatabasePath": "x.sdb"})
    plugin = make_plugin(InstalledShimDatabase, tmp_path)
    setup_keys(plugin, {_INSTALLED: make_node(children={_GUID: entry})})

    assert "AppCompatFlags" in plugin.run()[0].path


def test_installed_sdb_entry_without_a_path_is_skipped(tmp_path: Path) -> None:
    """A subkey carrying no DatabasePath yields nothing rather than a blank finding."""
    entry = make_node(name=_GUID, values={"DatabaseType": "65536"})
    plugin = make_plugin(InstalledShimDatabase, tmp_path)
    setup_keys(plugin, {_INSTALLED: make_node(children={_GUID: entry})})

    assert plugin.run() == []


def test_installed_sdb_absent_key_is_quiet(tmp_path: Path) -> None:
    """A host with no custom databases produces nothing."""
    plugin = make_plugin(InstalledShimDatabase, tmp_path)
    setup_keys(plugin, {})

    assert plugin.run() == []


def test_custom_reports_the_executable_and_its_database(tmp_path: Path) -> None:
    """A shimmed executable is reported together with the database bound to it."""
    exe = make_node(name="evil.exe", values={f"{_GUID}.sdb": "134327746937490872"})
    plugin = make_plugin(CustomShimmedExecutables, tmp_path)
    setup_keys(plugin, {_CUSTOM: make_node(children={"evil.exe": exe})})

    findings = plugin.run()

    assert len(findings) == 1
    assert "evil.exe" in findings[0].value
    assert findings[0].value.endswith(".sdb")


def test_custom_reports_every_database_bound_to_one_executable(tmp_path: Path) -> None:
    """An executable bound to two databases yields a finding for each."""
    exe = make_node(
        name="evil.exe",
        values={f"{_GUID}.sdb": "1", "{33334444-0000-0000-0000-000000000000}.sdb": "2"},
    )
    plugin = make_plugin(CustomShimmedExecutables, tmp_path)
    setup_keys(plugin, {_CUSTOM: make_node(children={"evil.exe": exe})})

    assert len(plugin.run()) == 2


def test_custom_ignores_values_that_are_not_databases(tmp_path: Path) -> None:
    """A value that does not name an .sdb is not reported as a shim binding."""
    exe = make_node(name="evil.exe", values={"SomeOtherValue": "1"})
    plugin = make_plugin(CustomShimmedExecutables, tmp_path)
    setup_keys(plugin, {_CUSTOM: make_node(children={"evil.exe": exe})})

    assert plugin.run() == []


def test_custom_absent_key_is_quiet(tmp_path: Path) -> None:
    """A host with no custom shim bindings produces nothing."""
    plugin = make_plugin(CustomShimmedExecutables, tmp_path)
    setup_keys(plugin, {})

    assert plugin.run() == []
