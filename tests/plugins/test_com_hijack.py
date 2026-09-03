"""Tests for the ComTreatAs COM class hijack plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.core.registry import RegistryNode
from pyrsistencesniper.plugins.T1546.com_hijack import ComTreatAs

from .conftest import make_node, make_plugin, make_user_profiles, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_MACHINE_NATIVE_KEY = r"Classes\CLSID"
_MACHINE_WOW64_KEY = r"Classes\Wow6432Node\CLSID"
_USRCLASS_NATIVE_KEY = "CLSID"
_USRCLASS_WOW64_KEY = r"Wow6432Node\CLSID"
_NTUSER_NATIVE_KEY = r"SOFTWARE\Classes\CLSID"

_EVIL_DLL = r"C:\Users\bob\AppData\Local\evil.dll"


def _clsid(name: str, **subkeys: str) -> RegistryNode:
    """Build one CLSID key whose named subkeys each carry a (Default) value."""
    return make_node(
        name=name,
        children={
            subkey: make_node(name=subkey, values={"(Default)": value})
            for subkey, value in subkeys.items()
        },
    )


def _clsid_tree(*clsid_nodes: RegistryNode) -> RegistryNode:
    """Build a CLSID container key holding the given CLSID subkeys."""
    return make_node(children={node.name: node for node in clsid_nodes})


class TestMachineTreatAs:
    """Machine CLSID trees are read in both registry views for TreatAs."""

    def test_native_view_treatas_is_reported(self, tmp_path: Path) -> None:
        """A TreatAs under the 64-bit machine CLSID tree is reported at its path."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid("{SOURCE}", TreatAs="{EVIL}"),
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == r"HKLM\SOFTWARE\Classes\CLSID\{SOURCE}\TreatAs"
        assert findings[0].value == "{EVIL}"
        assert findings[0].access_gained is AccessLevel.SYSTEM

    def test_wow6432node_view_treatas_is_reported(self, tmp_path: Path) -> None:
        """A 32-bit CLSID hijack lives beside the native tree and must be read too."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_WOW64_KEY: _clsid_tree(
                    _clsid(
                        "{0002DF01-0000-0000-C000-000000000046}",
                        TreatAs="{EVIL}",
                    ),
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKLM\SOFTWARE\Classes\Wow6432Node\CLSID"
            r"\{0002DF01-0000-0000-C000-000000000046}\TreatAs"
        )
        assert findings[0].access_gained is AccessLevel.SYSTEM

    def test_both_machine_views_are_reported_separately(self, tmp_path: Path) -> None:
        """The same CLSID hijacked in both views is two distinct registrations."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(_clsid("{SOURCE}", TreatAs="{EVIL}")),
                _MACHINE_WOW64_KEY: _clsid_tree(_clsid("{SOURCE}", TreatAs="{EVIL}")),
            },
        )

        assert [finding.path for finding in plugin.run()] == [
            r"HKLM\SOFTWARE\Classes\CLSID\{SOURCE}\TreatAs",
            r"HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{SOURCE}\TreatAs",
        ]

    def test_clsid_without_treatas_is_quiet(self, tmp_path: Path) -> None:
        """A CLSID key carrying no TreatAs subkey is not a finding."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(plugin, {_MACHINE_NATIVE_KEY: _clsid_tree(_clsid("{NORMAL}"))})

        assert plugin.run() == []

    def test_treatas_with_empty_default_is_quiet(self, tmp_path: Path) -> None:
        """A TreatAs holding a blank (Default) redirects nothing."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {_MACHINE_NATIVE_KEY: _clsid_tree(_clsid("{SOURCE}", TreatAs=""))},
        )

        assert plugin.run() == []

    def test_machine_server_registration_is_quiet(self, tmp_path: Path) -> None:
        """A live host has 6537 machine InprocServer32 keys; none is a hijack."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid("{STOCK}", InprocServer32=r"C:\Windows\system32\shell32.dll")
                )
            },
        )

        assert plugin.run() == []


class TestPerUserClsidHijack:
    """Per-user class registrations live in UsrClass.dat and are user-writable."""

    def test_usrclass_treatas_is_reported(self, tmp_path: Path) -> None:
        """A TreatAs written to UsrClass.dat needs no admin rights and must fire."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _USRCLASS_NATIVE_KEY: _clsid_tree(
                    _clsid("{SOURCE}", TreatAs="{EVIL}"),
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\alice\SOFTWARE\Classes\CLSID\{SOURCE}\TreatAs"
        )
        assert findings[0].access_gained is AccessLevel.USER

    def test_usrclass_wow6432node_treatas_is_reported(self, tmp_path: Path) -> None:
        """The 32-bit per-user class view is a fourth CLSID tree, also user-writable."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _USRCLASS_WOW64_KEY: _clsid_tree(
                    _clsid("{SOURCE}", TreatAs="{EVIL}"),
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\alice\SOFTWARE\Classes\Wow6432Node\CLSID\{SOURCE}\TreatAs"
        )

    def test_ntuser_classes_treatas_is_reported(self, tmp_path: Path) -> None:
        """An image whose class keys sit in NTUSER.DAT is still covered."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _NTUSER_NATIVE_KEY: _clsid_tree(
                    _clsid("{SOURCE}", TreatAs="{EVIL}"),
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\alice\SOFTWARE\Classes\CLSID\{SOURCE}\TreatAs"
        )

    def test_entry_in_both_user_hives_is_reported_once(self, tmp_path: Path) -> None:
        """NTUSER.DAT and UsrClass.dat share one canonical path, so one finding."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _USRCLASS_NATIVE_KEY: _clsid_tree(_clsid("{SOURCE}", TreatAs="{EVIL}")),
                _NTUSER_NATIVE_KEY: _clsid_tree(_clsid("{SOURCE}", TreatAs="{EVIL}")),
            },
        )

        assert len(plugin.run()) == 1

    def test_shadowing_inproc_server_is_reported(self, tmp_path: Path) -> None:
        """A per-user server on a machine-registered class is the classic hijack."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid(
                        "{FBEB8A05-BEEE-4442-804E-409D6C4515E9}",
                        InprocServer32=r"C:\Windows\system32\shell32.dll",
                    )
                ),
                _USRCLASS_NATIVE_KEY: _clsid_tree(
                    _clsid(
                        "{fbeb8a05-beee-4442-804e-409d6c4515e9}",
                        InprocServer32=_EVIL_DLL,
                    )
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\alice\SOFTWARE\Classes\CLSID"
            r"\{fbeb8a05-beee-4442-804e-409d6c4515e9}\InprocServer32"
        )
        assert findings[0].value == _EVIL_DLL
        assert findings[0].access_gained is AccessLevel.USER
        assert "machine-wide" in findings[0].description

    def test_shadowing_local_server_is_reported(self, tmp_path: Path) -> None:
        """An out-of-process server overrides the machine class as an in-proc one."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid("{SHARED}", LocalServer32=r"C:\Windows\system32\wbem.exe")
                ),
                _USRCLASS_NATIVE_KEY: _clsid_tree(
                    _clsid("{SHARED}", LocalServer32=r"C:\Users\bob\evil.exe")
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].value == r"C:\Users\bob\evil.exe"

    def test_shadowing_the_machine_wow64_view_is_reported(self, tmp_path: Path) -> None:
        """A class registered only in the 32-bit machine view is still shadowable."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _MACHINE_WOW64_KEY: _clsid_tree(
                    _clsid(
                        "{SHARED}",
                        InprocServer32=r"C:\Windows\SysWOW64\shell32.dll",
                    )
                ),
                _USRCLASS_WOW64_KEY: _clsid_tree(
                    _clsid("{SHARED}", InprocServer32=_EVIL_DLL)
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].path == (
            r"HKU\alice\SOFTWARE\Classes\Wow6432Node\CLSID\{SHARED}\InprocServer32"
        )

    # The OneDrive and Paint shape: a live Windows 11 profile carries 69
    # per-user server registrations, none overriding a machine-registered
    # class. Emitting them all put 69 entries at MEDIUM.
    def test_per_user_only_server_registration_is_quiet(self, tmp_path: Path) -> None:
        """An application's own per-user class shadows nothing and is not a hijack."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid(
                        "{UNRELATED}", InprocServer32=r"C:\Windows\system32\ole32.dll"
                    )
                ),
                _USRCLASS_NATIVE_KEY: _clsid_tree(
                    _clsid(
                        "{20894375-46AE-46E2-BAFD-CB38975CDCE6}",
                        InprocServer32=(
                            r"C:\Users\alice\AppData\Local\Microsoft\OneDrive"
                            r"\26.150.0804.0011\FileSyncShell64.dll"
                        ),
                    )
                ),
            },
        )

        assert plugin.run() == []


class TestForwardedServer:
    """The TreatAs target is resolved to the image the redirection ultimately loads."""

    def test_inproc_server_target_is_expanded(self, tmp_path: Path) -> None:
        """An InprocServer32 target is expanded and recorded for resolution."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid("{SOURCE}", TreatAs="{TARGET}"),
                    _clsid(
                        "{TARGET}",
                        InprocServer32=r"%SystemRoot%\system32\packager.dll",
                    ),
                )
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].resolve_target == r"Windows\system32\packager.dll"

    def test_unquoted_local_server_keeps_its_spaces(self, tmp_path: Path) -> None:
        """An unquoted LocalServer32 path keeps its spaces instead of truncating."""
        executable = r"C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE"
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid("{SOURCE}", TreatAs="{TARGET}"),
                    _clsid("{TARGET}", LocalServer32=executable),
                )
            },
        )

        assert plugin.run()[0].resolve_target == executable

    def test_dangling_target_resolves_to_nothing(self, tmp_path: Path) -> None:
        """A TreatAs target registered nowhere leaves resolve_target empty."""
        plugin = make_plugin(ComTreatAs, tmp_path)
        setup_keys(
            plugin,
            {_MACHINE_NATIVE_KEY: _clsid_tree(_clsid("{SOURCE}", TreatAs="{MISSING}"))},
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].resolve_target == ""

    def test_target_registered_only_per_user_is_resolved(self, tmp_path: Path) -> None:
        """A machine TreatAs forwarding into a per-user class still gets a signer."""
        plugin = make_plugin(
            ComTreatAs, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _MACHINE_NATIVE_KEY: _clsid_tree(
                    _clsid("{SOURCE}", TreatAs="{TARGET}")
                ),
                _USRCLASS_NATIVE_KEY: _clsid_tree(
                    _clsid("{TARGET}", InprocServer32=_EVIL_DLL)
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].resolve_target == _EVIL_DLL
