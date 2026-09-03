"""Tests for DLLOverridePath detection under ContentIndex\\Language (T1574)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1574.content_index_dll import ContentIndexDll

from .conftest import make_deps, make_node


def _make_plugin(tmp_path: Path) -> ContentIndexDll:
    """Build the plugin with mocked registry access; callers wire the hive lookups."""
    context, _registry, _filesystem = make_deps(tmp_path)
    return ContentIndexDll(context=context)


def _plugin_reading(tmp_path: Path, language_tree: object | None) -> ContentIndexDll:
    """Build the plugin over a SYSTEM hive answering with the given language tree."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SYSTEM")
    plugin.registry.open_hive.return_value = MagicMock()
    plugin.registry.load_subtree.return_value = language_tree
    return plugin


def test_dll_override_detected(tmp_path: Path) -> None:
    """DLLOverridePath names a DLL the indexer loads, so it is reported."""
    language_node = make_node(values={"DLLOverridePath": r"C:\evil.dll"})
    plugin = _plugin_reading(
        tmp_path, make_node(children={"English_US": language_node})
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == r"C:\evil.dll"
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert "DLLOverridePath" in findings[0].path


def test_no_override_no_finding(tmp_path: Path) -> None:
    """A language subkey without DLLOverridePath loads nothing and is not a finding."""
    language_node = make_node(values={"SomeOtherValue": "stuff"})
    plugin = _plugin_reading(
        tmp_path, make_node(children={"English_US": language_node})
    )

    assert plugin.run() == []


def test_missing_hive(tmp_path: Path) -> None:
    """An image with no SYSTEM hive is a clean absence, not a scan failure."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = None

    assert plugin.run() == []


def test_missing_language_key(tmp_path: Path) -> None:
    """A SYSTEM hive without the ContentIndex\\Language key yields nothing."""
    plugin = _plugin_reading(tmp_path, None)

    assert plugin.run() == []


def test_multiple_languages_with_override(tmp_path: Path) -> None:
    """Every language subkey is walked, so a second override does not hide."""
    english = make_node(values={"DLLOverridePath": r"C:\en.dll"})
    german = make_node(values={"DLLOverridePath": r"C:\de.dll"})
    plugin = _plugin_reading(
        tmp_path, make_node(children={"English_US": english, "German": german})
    )

    findings = plugin.run()

    assert {finding.value for finding in findings} == {r"C:\en.dll", r"C:\de.dll"}
