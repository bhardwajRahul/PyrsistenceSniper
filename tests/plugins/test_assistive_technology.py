"""Tests for AssistiveTechnology AT registrations and Configuration auto-start lists."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.assistive_technology import AssistiveTechnology

from .conftest import make_node, make_plugin, make_user_profiles, setup_keys

_ATS_KEY = r"Microsoft\Windows NT\CurrentVersion\Accessibility\ATs"
_ATS_KEY_WOW64 = r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs"
_ACCESSIBILITY_KEY = r"Software\Microsoft\Windows NT\CurrentVersion\Accessibility"
_CONFIGURATION_SUBKEY = (
    r"Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration"
)
_SIGN_IN_PATH = (
    r"HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion"
    r"\Accessibility\Configuration"
)


def _hives_present(*hive_names: str) -> Callable[..., Path | None]:
    """Return a hive_path side effect resolving only the machine hives named."""
    available = {hive_name.casefold() for hive_name in hive_names}

    def _hive_path(hive_name: str, username: str = "") -> Path | None:
        """Resolve a hive name to a fake path, or None when it was not collected."""
        if hive_name.casefold() not in available:
            return None
        return Path(f"/fake/{hive_name}")

    return _hive_path


class TestAssistiveTechnologyRegistrations:
    """ATs registered under the machine Accessibility key."""

    def test_registered_at_is_reported(self, tmp_path: Path) -> None:
        """An AT whose StartExe names a binary produces a SYSTEM finding."""
        plugin = make_plugin(AssistiveTechnology, tmp_path)
        plugin.context.hive_path.side_effect = _hives_present("SOFTWARE")
        at_node = make_node(name="EvilAT", values={"StartExe": r"C:\evil\at.exe"})
        setup_keys(plugin, {_ATS_KEY: make_node(children={"EvilAT": at_node})})

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            r"\Accessibility\ATs\EvilAT\StartExe"
        )
        assert findings[0].value == r"C:\evil\at.exe"
        assert findings[0].access_gained is AccessLevel.SYSTEM

    def test_start_params_are_appended(self, tmp_path: Path) -> None:
        """StartParams are reported alongside the binary they are passed to."""
        plugin = make_plugin(AssistiveTechnology, tmp_path)
        plugin.context.hive_path.side_effect = _hives_present("SOFTWARE")
        at_node = make_node(
            name="ParamAT",
            values={"StartExe": r"C:\tool.exe", "StartParams": "--evil"},
        )
        setup_keys(plugin, {_ATS_KEY: make_node(children={"ParamAT": at_node})})

        findings = plugin.run()

        assert [finding.value for finding in findings] == [r"C:\tool.exe --evil"]

    def test_wow6432node_registrations_are_reported(self, tmp_path: Path) -> None:
        """The 32-bit view of the ATs key is scanned as well as the native one."""
        plugin = make_plugin(AssistiveTechnology, tmp_path)
        plugin.context.hive_path.side_effect = _hives_present("SOFTWARE")
        at_node = make_node(name="WowAT", values={"StartExe": r"C:\evil\wow.exe"})
        setup_keys(plugin, {_ATS_KEY_WOW64: make_node(children={"WowAT": at_node})})

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path.startswith(
            r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT"
        )

    def test_numeric_start_exe_is_not_a_finding(self, tmp_path: Path) -> None:
        """Shipped ATs storing a flag rather than a binary are not persistence."""
        plugin = make_plugin(AssistiveTechnology, tmp_path)
        plugin.context.hive_path.side_effect = _hives_present("SOFTWARE")
        children = {
            "stickykeys": make_node(name="stickykeys", values={"StartExe": 4}),
            "highcontrast": make_node(name="highcontrast", values={"StartExe": "1"}),
            "cursorscheme": make_node(name="cursorscheme", values={"StartExe": ""}),
        }
        setup_keys(plugin, {_ATS_KEY: make_node(children=children)})

        assert plugin.run() == []


class TestAssistiveTechnologyUserConfiguration:
    """The per-user Configuration list that auto-starts ATs at logon."""

    def test_user_configuration_list_is_reported(self, tmp_path: Path) -> None:
        """Each AT named in a user's Configuration list becomes its own finding."""
        plugin = make_plugin(
            AssistiveTechnology, tmp_path, user_profiles=make_user_profiles("victim")
        )
        plugin.context.hive_path.side_effect = _hives_present()
        config = make_node(values={"Configuration": "EvilAT,CustomHelper"})
        setup_keys(plugin, {_ACCESSIBILITY_KEY: config})

        findings = plugin.run()

        assert len(findings) == 2
        assert all(
            finding.path
            == (
                r"HKU\victim\Software\Microsoft\Windows NT\CurrentVersion"
                r"\Accessibility\Configuration"
            )
            for finding in findings
        )
        assert {finding.value for finding in findings} == {"EvilAT", "CustomHelper"}
        assert all(finding.access_gained is AccessLevel.USER for finding in findings)

    def test_empty_configuration_is_not_a_finding(self, tmp_path: Path) -> None:
        """A user who auto-starts no AT leaves an empty list, not a finding."""
        plugin = make_plugin(
            AssistiveTechnology, tmp_path, user_profiles=make_user_profiles("victim")
        )
        plugin.context.hive_path.side_effect = _hives_present()
        setup_keys(
            plugin, {_ACCESSIBILITY_KEY: make_node(values={"Configuration": ""})}
        )

        assert plugin.run() == []

    def test_configuration_subkey_is_not_the_list(self, tmp_path: Path) -> None:
        """The list is a value on the Accessibility key, not a Configuration subkey."""
        plugin = make_plugin(
            AssistiveTechnology, tmp_path, user_profiles=make_user_profiles("victim")
        )
        plugin.context.hive_path.side_effect = _hives_present()
        config = make_node(values={"Configuration": "EvilAT"})
        setup_keys(plugin, {_CONFIGURATION_SUBKEY: config})

        assert plugin.run() == []


class TestAssistiveTechnologySignInDesktop:
    """The DEFAULT hive Configuration list that auto-starts ATs before logon."""

    def test_default_hive_configuration_is_reported(self, tmp_path: Path) -> None:
        """An AT wired into the DEFAULT hive list runs pre-logon, so as SYSTEM."""
        plugin = make_plugin(AssistiveTechnology, tmp_path)
        plugin.context.hive_path.side_effect = _hives_present("DEFAULT")
        config = make_node(values={"Configuration": "evilat"})
        setup_keys(plugin, {_ACCESSIBILITY_KEY: config})

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == _SIGN_IN_PATH
        assert findings[0].value == "evilat"
        assert findings[0].access_gained is AccessLevel.SYSTEM

    def test_default_hive_is_read_beside_the_user_hives(self, tmp_path: Path) -> None:
        """The sign-in list is reported in addition to every per-user list."""
        plugin = make_plugin(
            AssistiveTechnology, tmp_path, user_profiles=make_user_profiles("victim")
        )
        plugin.context.hive_path.side_effect = _hives_present("DEFAULT")
        config = make_node(values={"Configuration": "evilat"})
        setup_keys(plugin, {_ACCESSIBILITY_KEY: config})

        findings = plugin.run()

        assert {finding.access_gained for finding in findings} == {
            AccessLevel.USER,
            AccessLevel.SYSTEM,
        }
        assert _SIGN_IN_PATH in {finding.path for finding in findings}

    def test_uncollected_default_hive_is_not_a_finding(self, tmp_path: Path) -> None:
        """A collection without the DEFAULT hive reports no sign-in desktop entry."""
        plugin = make_plugin(AssistiveTechnology, tmp_path)
        plugin.context.hive_path.side_effect = _hives_present()
        config = make_node(values={"Configuration": "evilat"})
        setup_keys(plugin, {_ACCESSIBILITY_KEY: config})

        assert plugin.run() == []
