"""Tests for the PrintMonitors and PrintProcessors plugins (T1547.010/.012)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1547.print_monitors import (
    PrintMonitors,
    PrintProcessors,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path

_HAPPY_CASES: list[tuple[type, str, str]] = [
    (PrintMonitors, "evil_mon.dll", "T1547.010"),
    (PrintProcessors, "evil_proc.dll", "T1547.012"),
]


@pytest.mark.parametrize(
    ("plugin_cls", "driver_dll", "mitre_id"),
    _HAPPY_CASES,
    ids=[case[0].__name__ for case in _HAPPY_CASES],
)
def test_happy_path(
    tmp_path: Path,
    plugin_cls: type,
    driver_dll: str,
    mitre_id: str,
) -> None:
    """Each plugin flags a subkey carrying a Driver value."""
    child = make_node(name="EvilEntry", values={"Driver": driver_dll})
    tree = make_node(children={"EvilEntry": child})
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")
    findings = plugin.run()
    assert len(findings) >= 1
    assert any(driver_dll in finding.value for finding in findings)
    assert all(finding.access_gained == AccessLevel.SYSTEM for finding in findings)
    assert all(mitre_id in finding.mitre_id for finding in findings)


@pytest.mark.parametrize(
    "plugin_cls",
    [PrintMonitors, PrintProcessors],
    ids=lambda cls: cls.__name__,
)
def test_missing_driver_skipped(tmp_path: Path, plugin_cls: type) -> None:
    """A subkey without a Driver value produces no findings."""
    child = make_node(name="SomeEntry", values={"Other": "data"})
    tree = make_node(children={"SomeEntry": child})
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, tree, hive_path="/fake/SYSTEM")
    assert plugin.run() == []
