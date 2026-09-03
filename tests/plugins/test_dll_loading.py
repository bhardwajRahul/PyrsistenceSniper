"""Tests for all 19 DLL loading plugins in T1574/dll_loading.py."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1574.dll_loading import (
    AutodialDll,
    ChmHelper,
    CryptoExpoOffload,
    DiagTrackDll,
    DiagTrackListenerDll,
    Direct3dDll,
    GpExtensionDlls,
    HhctrlOcx,
    KnownManagedDebuggingDlls,
    LsaExtensions,
    Mapi32DllPath,
    MiniDumpAuxiliaryDlls,
    MsdtcXaDll,
    NaturalLanguageDevelopmentPlatform,
    RdpTestDvcPlugin,
    SearchIndexerDll,
    ServerLevelPluginDll,
    WinsockAutoProxy,
    WuServiceStartupDll,
)

from .conftest import (
    make_node,
    make_plugin,
    make_user_profiles,
    setup_hklm,
    setup_keys,
)

if TYPE_CHECKING:
    from pathlib import Path

_HHCTRL_CLSID = "{adb880a6-d8ff-11cf-9377-00aa003b7a11}"
_UNRELATED_CLSID = "{00000000-1111-2222-3333-444444444444}"
_WINSOCK_PARAMETERS = r"ControlSet001\Services\WinSock2\Parameters\NameSpace_Catalog5"

_DECLARATIVE_CASES: list[tuple[type, str, str, str]] = [
    (
        NaturalLanguageDevelopmentPlatform,
        "DllOverridePath",
        r"C:\evil.dll",
        "/fake/SOFTWARE",
    ),
    (ChmHelper, "Location", r"C:\evil_chm.dll", "/fake/SOFTWARE"),
    (AutodialDll, "AutodialDLL", r"C:\evil_autodial.dll", "/fake/SYSTEM"),
    (LsaExtensions, "Extensions", r"evil_lsa.dll", "/fake/SYSTEM"),
    (ServerLevelPluginDll, "ServerLevelPluginDll", r"C:\evil_dns.dll", "/fake/SYSTEM"),
    (CryptoExpoOffload, "ExpoOffload", r"C:\evil_crypto.dll", "/fake/SOFTWARE"),
    (Direct3dDll, "SoftwareRasterizer", r"C:\evil_d3d.dll", "/fake/SOFTWARE"),
    (MsdtcXaDll, "OracleXaLib", r"evil_xa.dll", "/fake/SOFTWARE"),
    (DiagTrackDll, "ImagePath", r"C:\evil_diag.exe", "/fake/SYSTEM"),
    (DiagTrackListenerDll, "FileName", r"C:\evil_listener.etl", "/fake/SYSTEM"),
    (RdpTestDvcPlugin, "TestDVCPlugin", r"C:\evil_rdp.dll", "/fake/SOFTWARE"),
    (SearchIndexerDll, "DllPath", r"C:\evil_search.dll", "/fake/SOFTWARE"),
    (WuServiceStartupDll, "ServiceDll", r"C:\evil_wu.dll", "/fake/SYSTEM"),
    (
        KnownManagedDebuggingDlls,
        "KnownManagedDebuggingDlls",
        r"C:\evil_dbg.dll",
        "/fake/SOFTWARE",
    ),
]


@pytest.mark.parametrize(
    ("plugin_cls", "value_key", "value_data", "hive_path"),
    _DECLARATIVE_CASES,
    ids=[case[0].__name__ for case in _DECLARATIVE_CASES],
)
def test_declarative_happy_path(
    tmp_path: Path,
    plugin_cls: type,
    value_key: str,
    value_data: str,
    hive_path: str,
) -> None:
    """Each declarative plugin produces a finding when its registry value is present."""
    node = make_node(values={value_key: value_data})
    plugin = make_plugin(plugin_cls, tmp_path)
    setup_hklm(plugin, node, hive_path=hive_path)
    findings = plugin.run()
    assert len(findings) >= 1
    assert any(value_data in finding.value for finding in findings)
    assert all("T1574" in finding.mitre_id for finding in findings)


class TestHhctrlOcx:
    """Cases for the hhctrl.ocx COM registration, which HKCU overrides for HKLM."""

    def test_machine_registration_fires(self, tmp_path: Path) -> None:
        """The 64-bit machine class registration is the baseline HKLM read."""
        plugin = make_plugin(HhctrlOcx, tmp_path)
        setup_keys(
            plugin,
            {
                rf"Classes\CLSID\{_HHCTRL_CLSID}\InprocServer32": make_node(
                    values={"(Default)": r"C:\ProgramData\evil.dll"}
                )
            },
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == (
            rf"HKLM\SOFTWARE\Classes\CLSID\{_HHCTRL_CLSID}\InprocServer32"
        )
        assert findings[0].value == r"C:\ProgramData\evil.dll"
        assert findings[0].access_gained is AccessLevel.SYSTEM

    def test_wow6432node_registration_fires(self, tmp_path: Path) -> None:
        """A 32-bit HTML Help host reads the redirected machine class registration."""
        plugin = make_plugin(HhctrlOcx, tmp_path)
        setup_keys(
            plugin,
            {
                rf"Classes\Wow6432Node\CLSID\{_HHCTRL_CLSID}"
                r"\InprocServer32": make_node(
                    values={"(Default)": r"C:\ProgramData\evil32.dll"}
                )
            },
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == (
            rf"HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\{_HHCTRL_CLSID}"
            r"\InprocServer32"
        )
        assert findings[0].value == r"C:\ProgramData\evil32.dll"

    def test_per_user_class_registration_fires(self, tmp_path: Path) -> None:
        """Per-user class registrations live in UsrClass.dat and override HKLM."""
        plugin = make_plugin(
            HhctrlOcx, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                rf"CLSID\{_HHCTRL_CLSID}\InprocServer32": make_node(
                    values={"(Default)": r"C:\Users\alice\AppData\Roaming\evil.dll"}
                )
            },
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == (
            rf"HKU\alice\SOFTWARE\Classes\CLSID\{_HHCTRL_CLSID}\InprocServer32"
        )
        assert findings[0].value == r"C:\Users\alice\AppData\Roaming\evil.dll"
        assert findings[0].access_gained is AccessLevel.USER

    def test_per_user_wow6432node_registration_fires(self, tmp_path: Path) -> None:
        """The 32-bit per-user class registration is the same hijack for WOW64 hosts."""
        plugin = make_plugin(
            HhctrlOcx, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                rf"Wow6432Node\CLSID\{_HHCTRL_CLSID}\InprocServer32": make_node(
                    values={"(Default)": r"C:\Users\alice\AppData\Roaming\evil32.dll"}
                )
            },
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == (
            rf"HKU\alice\SOFTWARE\Classes\Wow6432Node\CLSID\{_HHCTRL_CLSID}"
            r"\InprocServer32"
        )

    def test_another_per_user_clsid_stays_quiet(self, tmp_path: Path) -> None:
        """Widening to UsrClass.dat must not turn the check into a CLSID sweep."""
        plugin = make_plugin(
            HhctrlOcx, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                rf"CLSID\{_UNRELATED_CLSID}\InprocServer32": make_node(
                    values={"(Default)": r"C:\Users\alice\AppData\Local\OneDrive.dll"}
                )
            },
        )
        assert plugin.run() == []

    def test_same_registration_in_both_user_hives_reported_once(
        self, tmp_path: Path
    ) -> None:
        """NTUSER.DAT and UsrClass.dat share a canonical path, so one finding is due."""
        plugin = make_plugin(
            HhctrlOcx, tmp_path, user_profiles=make_user_profiles("alice")
        )
        registration = make_node(values={"(Default)": r"C:\ProgramData\evil.dll"})
        setup_keys(
            plugin,
            {
                rf"SOFTWARE\Classes\CLSID\{_HHCTRL_CLSID}"
                r"\InprocServer32": registration,
                rf"CLSID\{_HHCTRL_CLSID}\InprocServer32": registration,
            },
        )
        findings = plugin.run()
        assert len(findings) == 1


class TestMiniDumpAuxiliaryDlls:
    """Cases for MiniDumpAuxiliaryDlls, where the value name is the trigger module."""

    _KEY = r"Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls"
    _TRIGGER = r"C:\Windows\System32\chakra.dll"

    def test_reports_the_loaded_dll_not_the_trigger_module(
        self, tmp_path: Path
    ) -> None:
        """The value data is the DLL dbghelp loads, so it is the reported artifact."""
        node = make_node(values={self._TRIGGER: r"C:\Users\Public\evil.dll"})
        plugin = make_plugin(MiniDumpAuxiliaryDlls, tmp_path)
        setup_keys(plugin, {self._KEY: node})
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == r"C:\Users\Public\evil.dll"
        assert findings[0].path.endswith(self._TRIGGER)
        assert self._TRIGGER in findings[0].description
        assert findings[0].access_gained is AccessLevel.SYSTEM

    def test_trigger_module_is_never_the_reported_value(self, tmp_path: Path) -> None:
        """Reporting the signed trigger module hid the payload and must not return."""
        node = make_node(values={self._TRIGGER: r"C:\Users\Public\evil.dll"})
        plugin = make_plugin(MiniDumpAuxiliaryDlls, tmp_path)
        setup_keys(plugin, {self._KEY: node})
        assert all(finding.value != self._TRIGGER for finding in plugin.run())

    def test_entry_naming_no_auxiliary_dll_stays_quiet(self, tmp_path: Path) -> None:
        """An entry with no value data loads nothing and is not a finding."""
        node = make_node(values={self._TRIGGER: "  "})
        plugin = make_plugin(MiniDumpAuxiliaryDlls, tmp_path)
        setup_keys(plugin, {self._KEY: node})
        assert plugin.run() == []

    def test_empty_name_skipped(self, tmp_path: Path) -> None:
        """A whitespace-only name identifies no trigger module and is not a finding."""
        node = make_node(values={"  ": r"C:\Users\Public\evil.dll"})
        plugin = make_plugin(MiniDumpAuxiliaryDlls, tmp_path)
        setup_keys(plugin, {self._KEY: node})
        assert plugin.run() == []

    def test_undeclared_key_stays_quiet(self, tmp_path: Path) -> None:
        """The check reads one key path, not whatever subtree the hive hands it."""
        node = make_node(values={self._TRIGGER: r"C:\Users\Public\evil.dll"})
        plugin = make_plugin(MiniDumpAuxiliaryDlls, tmp_path)
        setup_keys(plugin, {r"Microsoft\Windows NT\CurrentVersion": node})
        assert plugin.run() == []


class TestMapi32DllPath:
    """Cases for MAPI providers, registered one subkey per mail client."""

    def test_client_subkey_dllpathex_fires(self, tmp_path: Path) -> None:
        """DLLPathEx under a client subkey names the DLL every MAPI process loads."""
        client = make_node(
            name="Microsoft Outlook",
            values={"DLLPathEx": r"C:\ProgramData\evil.dll"},
        )
        plugin = make_plugin(Mapi32DllPath, tmp_path)
        setup_keys(
            plugin,
            {r"Clients\Mail": make_node(children={"Microsoft Outlook": client})},
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == (
            r"HKLM\SOFTWARE\Clients\Mail\Microsoft Outlook\DLLPathEx"
        )
        assert findings[0].value == r"C:\ProgramData\evil.dll"

    def test_client_subkey_legacy_dllpath_fires(self, tmp_path: Path) -> None:
        """The legacy DLLPath value is still honoured by the MAPI stub."""
        client = make_node(
            name="Hotmail",
            values={"DLLPath": r"C:\ProgramData\evil_legacy.dll"},
        )
        plugin = make_plugin(Mapi32DllPath, tmp_path)
        setup_keys(plugin, {r"Clients\Mail": make_node(children={"Hotmail": client})})
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == r"HKLM\SOFTWARE\Clients\Mail\Hotmail\DLLPath"

    def test_wow6432node_client_subkey_fires(self, tmp_path: Path) -> None:
        """A 32-bit MAPI application resolves its provider from the redirected view."""
        client = make_node(
            name="Hotmail", values={"DLLPathEx": r"C:\ProgramData\evil32.dll"}
        )
        plugin = make_plugin(Mapi32DllPath, tmp_path)
        setup_keys(
            plugin,
            {r"Wow6432Node\Clients\Mail": make_node(children={"Hotmail": client})},
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path == (
            r"HKLM\SOFTWARE\Wow6432Node\Clients\Mail\Hotmail\DLLPathEx"
        )

    def test_value_on_the_parent_key_stays_quiet(self, tmp_path: Path) -> None:
        """Clients\\Mail itself carries no provider DLL; reading it found nothing."""
        plugin = make_plugin(Mapi32DllPath, tmp_path)
        setup_keys(
            plugin,
            {r"Clients\Mail": make_node(values={"DLLPath": r"C:\ProgramData\x.dll"})},
        )
        assert plugin.run() == []

    def test_client_without_a_provider_dll_stays_quiet(self, tmp_path: Path) -> None:
        """A mail client registering no MAPI provider loads nothing and is not shown."""
        client = make_node(values={"LocalizedString": "@hmmapi.dll,-203"})
        plugin = make_plugin(Mapi32DllPath, tmp_path)
        setup_keys(plugin, {r"Clients\Mail": make_node(children={"Hotmail": client})})
        assert plugin.run() == []


class TestGpExtensionDlls:
    """Cases for Group Policy extension DLLs, one GUID subkey per extension."""

    def test_happy_path(self, tmp_path: Path) -> None:
        """The DllName under a GUID subkey is loaded at every policy refresh."""
        child = make_node(values={"DllName": r"C:\evil_gp.dll"})
        tree = make_node(children={"{evil-guid}": child})
        plugin = make_plugin(GpExtensionDlls, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SOFTWARE")
        findings = plugin.run()
        assert len(findings) >= 1
        assert any("evil_gp.dll" in finding.value for finding in findings)
        assert all("T1574" in finding.mitre_id for finding in findings)

    def test_child_without_dllname_skipped(self, tmp_path: Path) -> None:
        """A GUID subkey with no DllName loads nothing and is not reported."""
        child = make_node(values={"OtherValue": "irrelevant"})
        tree = make_node(children={"{some-guid}": child})
        plugin = make_plugin(GpExtensionDlls, tmp_path)
        setup_hklm(plugin, tree, hive_path="/fake/SOFTWARE")
        findings = plugin.run()
        assert findings == []


class TestWinsockAutoProxy:
    """Cases for the two Winsock namespace catalogs, keyed by catalog index."""

    def test_native_catalog_fires(self, tmp_path: Path) -> None:
        """LibraryPath in a catalog entry is the DLL every networking process loads."""
        child = make_node(
            name="000000000006", values={"LibraryPath": r"C:\evil_winsock.dll"}
        )
        plugin = make_plugin(WinsockAutoProxy, tmp_path)
        setup_keys(
            plugin,
            {
                rf"{_WINSOCK_PARAMETERS}\Catalog_Entries": make_node(
                    children={"000000000006": child}
                )
            },
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path.endswith(
            r"NameSpace_Catalog5\Catalog_Entries\000000000006\LibraryPath"
        )
        assert findings[0].value == r"C:\evil_winsock.dll"

    def test_catalog_entries64_fires(self, tmp_path: Path) -> None:
        """Catalog_Entries64 is the catalog 64-bit processes actually consult."""
        child = make_node(
            name="000000000006", values={"LibraryPath": r"C:\ProgramData\evil.dll"}
        )
        plugin = make_plugin(WinsockAutoProxy, tmp_path)
        setup_keys(
            plugin,
            {
                rf"{_WINSOCK_PARAMETERS}\Catalog_Entries64": make_node(
                    children={"000000000006": child}
                )
            },
        )
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path.endswith(
            r"NameSpace_Catalog5\Catalog_Entries64\000000000006\LibraryPath"
        )
        assert findings[0].value == r"C:\ProgramData\evil.dll"

    def test_child_without_librarypath_skipped(self, tmp_path: Path) -> None:
        """A catalog entry without LibraryPath names no DLL and yields nothing."""
        child = make_node(values={"OtherValue": "irrelevant"})
        entries = make_node(children={"000000000001": child})
        plugin = make_plugin(WinsockAutoProxy, tmp_path)
        setup_keys(
            plugin,
            {
                rf"{_WINSOCK_PARAMETERS}\Catalog_Entries": entries,
                rf"{_WINSOCK_PARAMETERS}\Catalog_Entries64": entries,
            },
        )
        assert plugin.run() == []

    def test_sibling_protocol_catalog_stays_quiet(self, tmp_path: Path) -> None:
        """A second catalog must not widen the check to every Winsock catalog."""
        child = make_node(
            name="000000000006", values={"LibraryPath": r"C:\ProgramData\evil.dll"}
        )
        plugin = make_plugin(WinsockAutoProxy, tmp_path)
        setup_keys(
            plugin,
            {
                r"ControlSet001\Services\WinSock2\Parameters"
                r"\Protocol_Catalog9\Catalog_Entries64": make_node(
                    children={"000000000001": child}
                )
            },
        )
        assert plugin.run() == []
