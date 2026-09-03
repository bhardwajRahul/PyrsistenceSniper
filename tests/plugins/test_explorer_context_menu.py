"""Tests for the Explorer context menu handler plugin (T1547)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1547.explorer_context_menu import ExplorerContextMenu

from .conftest import (
    make_node,
    make_plugin,
    make_user_profiles,
    setup_keys,
    setup_usrclass_only,
)

_MACHINE_DIRECTORY = r"Classes\Directory\shellex\ContextMenuHandlers"
_USER_DIRECTORY = r"Directory\shellex\ContextMenuHandlers"
_EVIL_DLL = r"C:\Users\bob\AppData\Roaming\evil.dll"
_CLSID = "{AAAA-BBBB}"


def _handler_tree(handler_name: str, value: str) -> object:
    """Build a ContextMenuHandlers subtree holding one handler subkey."""
    handler = make_node(name=handler_name, values={"(Default)": value})
    return make_node(children={handler_name: handler})


class TestMachineContextMenuHandlers:
    """Cases for the machine-wide SOFTWARE\\Classes half of HKCR."""

    def test_handler_with_clsid_resolved_to_dll(self, tmp_path: Path) -> None:
        """A handler is reported by the DLL its CLSID resolves to, not by the CLSID."""
        plugin = make_plugin(ExplorerContextMenu, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_DIRECTORY: _handler_tree("EvilHandler", _CLSID),
                rf"Classes\CLSID\{_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _EVIL_DLL}
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].value == _EVIL_DLL
        assert findings[0].path == (
            r"HKLM\SOFTWARE\Classes\Directory\shellex"
            r"\ContextMenuHandlers\EvilHandler"
        )
        assert findings[0].access_gained is AccessLevel.SYSTEM
        assert "T1547" in findings[0].mitre_id

    def test_thirty_two_bit_handler_clsid_resolved(self, tmp_path: Path) -> None:
        """A 32-bit shell extension registers its DLL under Classes\\Wow6432Node."""
        plugin = make_plugin(ExplorerContextMenu, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_DIRECTORY: _handler_tree("EvilHandler", _CLSID),
                rf"Classes\Wow6432Node\CLSID\{_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _EVIL_DLL}
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].value == _EVIL_DLL

    @pytest.mark.parametrize(
        "subject",
        [
            "Directory",
            r"Directory\Background",
            "Folder",
            "Drive",
            "AllFilesystemObjects",
            "*",
        ],
    )
    def test_every_explorer_subject_is_scanned(
        self, subject: str, tmp_path: Path
    ) -> None:
        """Explorer loads handlers from each of these class subjects."""
        plugin = make_plugin(ExplorerContextMenu, tmp_path)
        setup_keys(
            plugin,
            {
                rf"Classes\{subject}\shellex\ContextMenuHandlers": _handler_tree(
                    "EvilHandler", _EVIL_DLL
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            rf"HKLM\SOFTWARE\Classes\{subject}\shellex"
            r"\ContextMenuHandlers\EvilHandler"
        )

    def test_undeclared_subject_stays_quiet(self, tmp_path: Path) -> None:
        """A shellex key under a class Explorer never consults is not a finding."""
        plugin = make_plugin(ExplorerContextMenu, tmp_path)
        setup_keys(
            plugin,
            {
                r"Classes\Printers\shellex\ContextMenuHandlers": _handler_tree(
                    "SomeHandler", _EVIL_DLL
                )
            },
        )

        assert plugin.run() == []

    def test_clsid_without_inprocserver32_still_reported(self, tmp_path: Path) -> None:
        """An unresolvable CLSID is reported as itself rather than dropped."""
        plugin = make_plugin(ExplorerContextMenu, tmp_path)
        setup_keys(plugin, {_MACHINE_DIRECTORY: _handler_tree("Handler", _CLSID)})

        findings = plugin.run()

        assert len(findings) == 1
        assert _CLSID in findings[0].value

    def test_non_clsid_non_path_handler_stays_quiet(self, tmp_path: Path) -> None:
        """Naming neither a CLSID nor a file leaves no code to report."""
        plugin = make_plugin(ExplorerContextMenu, tmp_path)
        setup_keys(
            plugin,
            {_MACHINE_DIRECTORY: _handler_tree("PlainHandler", "Start Menu Pin")},
        )

        assert plugin.run() == []

    def test_uncollected_hive_returns_empty(self, tmp_path: Path) -> None:
        """An image without a SOFTWARE hive is a clean absence, not a scan failure."""
        plugin = make_plugin(ExplorerContextMenu, tmp_path)
        plugin.context.hive_path.return_value = None

        assert plugin.run() == []


class TestPerUserContextMenuHandlers:
    """Cases for the user-writable UsrClass.dat half of HKCR."""

    def test_per_user_handler_read_from_the_hive_root(self, tmp_path: Path) -> None:
        """UsrClass.dat's root is HKCU\\Software\\Classes, so the prefix is dropped."""
        plugin = make_plugin(
            ExplorerContextMenu, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_keys(
            plugin,
            {
                _USER_DIRECTORY: _handler_tree("Evil", _CLSID),
                rf"CLSID\{_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _EVIL_DLL}
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\victim\Software\Classes\Directory\shellex"
            r"\ContextMenuHandlers\Evil"
        )
        assert findings[0].value == _EVIL_DLL
        assert findings[0].access_gained is AccessLevel.USER

    def test_per_user_handler_not_read_from_a_prefixed_path(
        self, tmp_path: Path
    ) -> None:
        """A hive answering only the machine-shaped path yields nothing per user."""
        plugin = make_plugin(
            ExplorerContextMenu, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_keys(
            plugin,
            {
                r"Software\Classes\Directory\shellex\ContextMenuHandlers": (
                    _handler_tree("Evil", _EVIL_DLL)
                )
            },
        )

        assert plugin.run() == []

    def test_per_user_handler_falls_back_to_the_machine_clsid(
        self, tmp_path: Path
    ) -> None:
        """A per-user handler may point at a machine-wide CLSID registration."""
        plugin = make_plugin(
            ExplorerContextMenu, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_keys(
            plugin,
            {
                _USER_DIRECTORY: _handler_tree("Evil", _CLSID),
                rf"Classes\CLSID\{_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _EVIL_DLL}
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].value == _EVIL_DLL
        assert findings[0].access_gained is AccessLevel.USER

    def test_per_user_handler_is_read_out_of_usrclass_not_ntuser(
        self, tmp_path: Path
    ) -> None:
        """Per-user class registrations live in UsrClass.dat and nowhere else."""
        plugin = make_plugin(
            ExplorerContextMenu, tmp_path, user_profiles=make_user_profiles("victim")
        )
        setup_usrclass_only(plugin, {_USER_DIRECTORY: _handler_tree("Evil", _EVIL_DLL)})

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path.startswith(r"HKU\victim\Software\Classes\Directory")

    def test_profile_without_usrclass_is_skipped(self, tmp_path: Path) -> None:
        """A profile whose UsrClass.dat was never collected contributes nothing."""
        profile = UserProfile(
            username="victim",
            profile_path=tmp_path / "Users" / "victim",
            ntuser_path=tmp_path / "NTUSER.DAT",
            usrclass_path=None,
        )
        plugin = make_plugin(ExplorerContextMenu, tmp_path, user_profiles=[profile])
        setup_keys(plugin, {_USER_DIRECTORY: _handler_tree("Evil", _EVIL_DLL)})

        assert plugin.run() == []
