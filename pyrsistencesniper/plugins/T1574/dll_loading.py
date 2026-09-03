"""Detections for registry keys that name a DLL the Windows loader will load."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class NaturalLanguageDevelopmentPlatform(PersistencePlugin):
    """Detects NLDP DLL Override persistence entries."""

    definition = CheckDefinition(
        id="nldp_dll",
        technique="NLDP DLL Override",
        mitre_id="T1574.001",
        description=(
            "The NlsData DllOverridePath specifies a custom DLL loaded by "
            "the Natural Language Processing subsystem. Any value present "
            "indicates DLL hijacking persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NlsData",
                values="DllOverridePath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class ChmHelper(PersistencePlugin):
    """Detects CHM Helper DLL persistence entries."""

    definition = CheckDefinition(
        id="chm_helper_dll",
        technique="CHM Helper DLL",
        mitre_id="T1574.001",
        description=(
            "The CHM helper DLL Location value specifies a DLL loaded when "
            "rendering compiled HTML help files. Hijacking this provides "
            "code execution when .chm files are opened."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\HtmlHelp Author",
                values="Location",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class HhctrlOcx(PersistencePlugin):
    """Detects hhctrl.ocx DLL Override persistence entries."""

    definition = CheckDefinition(
        id="hhctrl_ocx_dll",
        technique="hhctrl.ocx DLL Override",
        mitre_id="T1574.001",
        description=(
            "The hhctrl.ocx CLSID InprocServer32 points to the DLL loaded "
            "for HTML Help controls. Hijacking this COM registration "
            "provides code execution when any HTML Help content is rendered."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SOFTWARE\Classes\CLSID"
                    r"\{adb880a6-d8ff-11cf-9377-00aa003b7a11}\InprocServer32"
                ),
                values="(Default)",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
        ),
    )


@register_plugin
class AutodialDll(PersistencePlugin):
    """Detects AutodialDLL Override persistence entries."""

    definition = CheckDefinition(
        id="autodial_dll",
        technique="AutodialDLL Override",
        mitre_id="T1574.001",
        description=(
            "The AutodialDLL value specifies a DLL loaded by the WinSock "
            "auto-dial feature. A non-OS DLL provides persistent code "
            "execution in any process that uses WinSock."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\WinSock2\Parameters",
                values="AutodialDLL",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class LsaExtensions(PersistencePlugin):
    """Detects LSA Extensions DLL persistence entries."""

    definition = CheckDefinition(
        id="lsa_extensions",
        technique="LSA Extensions DLL",
        mitre_id="T1574.001",
        description=(
            "LSA Extensions are DLLs loaded by the Local Security Authority "
            "during system startup. A malicious extension can intercept "
            "credentials and provide SYSTEM-level persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\LsaExtensionConfig\LsaSrv",
                values="Extensions",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class ServerLevelPluginDll(PersistencePlugin):
    """Detects DNS Server Level Plugin DLL persistence entries."""

    definition = CheckDefinition(
        id="server_level_plugin_dll",
        technique="DNS Server Level Plugin DLL",
        mitre_id="T1574.001",
        description=(
            "The DNS Server ServerLevelPluginDll value specifies a DLL "
            "loaded by the DNS service at startup. Abuse provides "
            "SYSTEM-level persistence on domain controllers."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\DNS\Parameters",
                values="ServerLevelPluginDll",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class CryptoExpoOffload(PersistencePlugin):
    """Detects Crypto ExpoOffload DLL persistence entries."""

    definition = CheckDefinition(
        id="crypto_expo_offload",
        technique="Crypto ExpoOffload DLL",
        mitre_id="T1574.001",
        description=(
            "The ExpoOffload value specifies a DLL loaded by the "
            "cryptography subsystem for exponentiation offloading. Any "
            "value present indicates potential DLL hijacking persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Cryptography\Offload",
                values="ExpoOffload",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class Direct3dDll(PersistencePlugin):
    """Detects Direct3D Software Rasterizer DLL persistence entries."""

    definition = CheckDefinition(
        id="direct3d_dll",
        technique="Direct3D Software Rasterizer DLL",
        mitre_id="T1574.001",
        description=(
            "The D3D SoftwareRasterizer value specifies the DLL loaded as "
            "the Direct3D software rasterizer. Hijacking provides code "
            "execution in any process that initializes Direct3D."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Direct3D\Drivers",
                values="SoftwareRasterizer",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class MsdtcXaDll(PersistencePlugin):
    """Detects MSDTC XA DLL persistence entries."""

    definition = CheckDefinition(
        id="msdtc_xa_dll",
        technique="MSDTC XA DLL",
        mitre_id="T1574.001",
        description=(
            "MSDTC XA DLLs (OracleXaLib, OracleOciLib) are loaded by the "
            "Distributed Transaction Coordinator. A malicious DLL executes "
            "in the SYSTEM context of the MSDTC service."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\MSDTC\MTxOCI",
                values="OracleXaLib",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\MSDTC\MTxOCI",
                values="OracleOciLib",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class DiagTrackDll(PersistencePlugin):
    """Detects DiagTrack DLL persistence entries."""

    definition = CheckDefinition(
        id="diagtrack_dll",
        technique="DiagTrack DLL",
        mitre_id="T1574.001",
        description=(
            "The DiagTrack service ImagePath specifies the service binary. "
            "Replacing it with a non-OS executable provides SYSTEM-level "
            "persistence triggered by the telemetry service."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\DiagTrack",
                values="ImagePath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class DiagTrackListenerDll(PersistencePlugin):
    """Detects DiagTrack Listener DLL persistence entries."""

    definition = CheckDefinition(
        id="diagtrack_listener_dll",
        technique="DiagTrack Listener DLL",
        mitre_id="T1574.001",
        description=(
            "The DiagTrack Autologger listener FileName specifies the DLL "
            "loaded for telemetry collection. Hijacking this value provides "
            "SYSTEM-level persistence at boot."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\WMI\Autologger\DiagTrack-Listener",
                values="FileName",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class RdpTestDvcPlugin(PersistencePlugin):
    """Detects RDP TestDVCPlugin DLL persistence entries."""

    definition = CheckDefinition(
        id="rdp_test_dvc_plugin",
        technique="RDP TestDVCPlugin DLL",
        mitre_id="T1574.001",
        description=(
            "The TestDVCPlugin value specifies a DLL loaded by the RDP "
            "client for Dynamic Virtual Channel testing. Any value present "
            "indicates potential DLL-based persistence via RDP sessions."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Terminal Server Client",
                values="TestDVCPlugin",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class SearchIndexerDll(PersistencePlugin):
    """Detects Search Indexer DLL Override persistence entries."""

    definition = CheckDefinition(
        id="search_indexer_dll",
        technique="Search Indexer DLL Override",
        mitre_id="T1574.001",
        description=(
            "The Windows Search Indexer DllPath value can be overridden to "
            "load a malicious DLL during indexing operations, providing "
            "SYSTEM-level persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows Search",
                values="DllPath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WuServiceStartupDll(PersistencePlugin):
    """Detects Windows Update Service Startup DLL persistence entries."""

    definition = CheckDefinition(
        id="wu_service_startup_dll",
        technique="Windows Update Service Startup DLL",
        mitre_id="T1574.001",
        description=(
            "The Windows Update ServiceDll value specifies the DLL loaded "
            "by the wuauserv service. A non-OS DLL provides SYSTEM-level "
            "persistence triggered by Windows Update operations."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\wuauserv\Parameters",
                values="ServiceDll",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class KnownManagedDebuggingDlls(PersistencePlugin):
    """Detects Known Managed Debugging DLLs persistence entries."""

    definition = CheckDefinition(
        id="known_managed_debugging_dlls",
        technique="Known Managed Debugging DLLs",
        mitre_id="T1574.001",
        description=(
            "KnownManagedDebuggingDlls specifies DLLs loaded by .NET "
            "managed debuggers. Registering a malicious DLL provides "
            "code execution whenever managed debugging is initiated."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="KnownManagedDebuggingDlls",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class MiniDumpAuxiliaryDlls(PersistencePlugin):
    """Detects MiniDump Auxiliary DLLs persistence entries."""

    definition = CheckDefinition(
        id="minidump_auxiliary_dlls",
        technique="MiniDump Auxiliary DLLs",
        mitre_id="T1574.001",
        description=(
            "MiniDumpAuxiliaryDlls entries name a trigger module and the "
            "auxiliary DLL dbghelp loads into the dumping process when that "
            "module is present. The auxiliary DLL runs during every crash "
            "dump, so registering one here provides code execution."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
    )

    def run(self) -> list[Finding]:
        """Report the auxiliary DLL each MiniDumpAuxiliaryDlls entry loads."""
        findings: list[Finding] = []

        key_path = r"Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls"
        tree = self.context.load_subtree("SOFTWARE", key_path)
        if tree is None:
            return findings

        for trigger_module, auxiliary_dll in tree.values():
            if not trigger_module.strip():
                continue
            auxiliary_dll_path = registry_value_to_str(auxiliary_dll)
            if auxiliary_dll_path is None:
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{key_path}\\{trigger_module}",
                    value=auxiliary_dll_path,
                    access=AccessLevel.SYSTEM,
                    description=(
                        f"{self.definition.description} "
                        f"(trigger module: {trigger_module})"
                    ),
                )
            )

        return findings


@register_plugin
class Mapi32DllPath(PersistencePlugin):
    """Detects MAPI32 DLL Path Override persistence entries."""

    definition = CheckDefinition(
        id="mapi32_dll_path",
        technique="MAPI32 DLL Path Override",
        mitre_id="T1574.001",
        description=(
            "Every mail client registers its MAPI provider in a subkey of "
            "Clients Mail, where DLLPathEx (or the legacy DLLPath) names "
            "the DLL loaded by every process that initialises MAPI. "
            "Hijacking it provides code execution in Outlook and in any "
            "application that sends mail."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Clients\Mail",
                values="DLLPathEx",
                scope=HiveScope.HKLM,
                recurse=True,
                include_wow64=True,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Clients\Mail",
                values="DLLPath",
                scope=HiveScope.HKLM,
                recurse=True,
                include_wow64=True,
            ),
        ),
    )


@register_plugin
class GpExtensionDlls(PersistencePlugin):
    """Detects Group Policy Extension DLLs persistence entries."""

    definition = CheckDefinition(
        id="gp_extension_dlls",
        technique="Group Policy Extension DLLs",
        mitre_id="T1574.001",
        description=(
            "Group Policy Extension DLLs are loaded by the GP engine "
            "during policy refresh. A non-OS DLL registered here provides "
            "SYSTEM-level persistence triggered at every gpupdate cycle."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\Winlogon\GPExtensions"
                ),
                values="DllName",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )


@register_plugin
class WinsockAutoProxy(PersistencePlugin):
    """Detects Winsock AutoProxy DLL persistence entries."""

    definition = CheckDefinition(
        id="winsock_auto_proxy",
        technique="Winsock AutoProxy DLL",
        mitre_id="T1574.001",
        description=(
            "Winsock NameSpace_Catalog5 provider DLLs are loaded for "
            "network name resolution. A non-OS library in either the "
            "32-bit or the 64-bit catalog provides persistent DLL loading "
            "in any networking process."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SYSTEM\{controlset}\Services\WinSock2\Parameters"
                    r"\NameSpace_Catalog5\Catalog_Entries"
                ),
                values="LibraryPath",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
            RegistryTarget(
                path=(
                    r"SYSTEM\{controlset}\Services\WinSock2\Parameters"
                    r"\NameSpace_Catalog5\Catalog_Entries64"
                ),
                values="LibraryPath",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )
