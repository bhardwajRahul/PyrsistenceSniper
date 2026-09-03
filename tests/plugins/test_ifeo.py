"""Tests for the IFEO plugins: Debugger, SilentProcessExit, and VerifierDlls."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1546.ifeo import (
    IfeoDebugger,
    IfeoDelegatedNtdll,
    IfeoSilentProcessExit,
)

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_IFEO_KEY = r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_SPE_KEY = r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
_WOW64_IFEO_KEY = (
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion"
    r"\Image File Execution Options"
)
_WOW64_SPE_KEY = r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"


def _wire_key(plugin: object, key_path: str, tree_node: object) -> None:
    """Wire one subtree at the literal key path the plugin under test must read."""
    setup_keys(plugin, {key_path: tree_node})


class TestIfeoDebugger:
    """Cases for the IFEO Debugger value, which redirects a named executable."""

    def test_happy_path(self, tmp_path: Path) -> None:
        """A Debugger entry runs when the named image starts, so it earns SYSTEM."""
        image_key = make_node(name="notepad.exe", values={"Debugger": "evil.exe"})
        tree = make_node(children={"notepad.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "evil.exe"
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert findings[0].path == (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\notepad.exe\\Debugger"
        )

    def test_no_debugger_value(self, tmp_path: Path) -> None:
        """A subkey holding other IFEO tuning is normal and must not be flagged."""
        image_key = make_node(name="notepad.exe", values={"SomeOther": "val"})
        tree = make_node(children={"notepad.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        assert plugin.run() == []

    def test_multiple_subkeys(self, tmp_path: Path) -> None:
        """Each hijacked image is its own finding, so none hides behind the first."""
        first_image = make_node(name="a.exe", values={"Debugger": "bad1.exe"})
        second_image = make_node(name="b.exe", values={"Debugger": "bad2.exe"})
        tree = make_node(children={"a.exe": first_image, "b.exe": second_image})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        assert len(plugin.run()) == 2

    def test_debugger_behind_use_filter_subkey(self, tmp_path: Path) -> None:
        """UseFilter moves the Debugger one level down, where it still hijacks."""
        filter_key = make_node(
            name="{a1b2c3d4}",
            values={
                "FilterFullPath": "C:\\Windows\\System32\\notepad.exe",
                "Debugger": "C:\\ProgramData\\svc.exe",
            },
        )
        image_key = make_node(
            name="notepad.exe",
            values={"UseFilter": 1},
            children={"{a1b2c3d4}": filter_key},
        )
        tree = make_node(children={"notepad.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "C:\\ProgramData\\svc.exe"
        assert findings[0].path == (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\notepad.exe\\{a1b2c3d4}\\Debugger"
        )

    def test_shipped_alias_redirect_filters_stay_quiet(self, tmp_path: Path) -> None:
        """Windows ships notepad.exe filter subkeys with no Debugger; stay silent."""
        filters = {
            name: make_node(
                name=name,
                values={
                    "AppExecutionAliasRedirect": 1,
                    "AppExecutionAliasRedirectPackages": "*",
                    "FilterFullPath": full_path,
                },
            )
            for name, full_path in (
                ("0", "C:\\Windows\\System32\\notepad.exe"),
                ("1", "C:\\Windows\\SysWOW64\\notepad.exe"),
                ("2", "C:\\Windows\\notepad.exe"),
            )
        }
        image_key = make_node(
            name="notepad.exe",
            values={"UseFilter": 1},
            children=filters,
        )
        tree = make_node(children={"notepad.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        assert plugin.run() == []

    def test_debugger_two_levels_below_image_key(self, tmp_path: Path) -> None:
        """Depth is not assumed, so a Debugger buried deeper is still reported."""
        deepest = make_node(name="inner", values={"Debugger": "evil.exe"})
        middle = make_node(name="outer", children={"inner": deepest})
        image_key = make_node(name="notepad.exe", children={"outer": middle})
        tree = make_node(children={"notepad.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path.endswith(
            "\\Image File Execution Options\\notepad.exe\\outer\\inner\\Debugger"
        )

    def test_debugger_in_wow6432node_view(self, tmp_path: Path) -> None:
        """A Debugger written through the redirector must not stay invisible."""
        image_key = make_node(name="setup32.exe", values={"Debugger": "evil32.exe"})
        tree = make_node(children={"setup32.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _WOW64_IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "evil32.exe"
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert findings[0].path == (
            "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Image File Execution Options"
            "\\setup32.exe\\Debugger"
        )

    def test_wow6432node_filter_subkey_searched(self, tmp_path: Path) -> None:
        """The 32-bit view gets the same subtree recursion as the native one."""
        filter_key = make_node(
            name="{b2}",
            values={
                "FilterFullPath": "C:\\Windows\\SysWOW64\\setup32.exe",
                "Debugger": "C:\\ProgramData\\svc32.exe",
            },
        )
        image_key = make_node(
            name="setup32.exe", values={"UseFilter": 1}, children={"{b2}": filter_key}
        )
        tree = make_node(children={"setup32.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _WOW64_IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path.endswith(
            "\\Image File Execution Options\\setup32.exe\\{b2}\\Debugger"
        )

    def test_wow6432node_mitigation_only_stays_quiet(self, tmp_path: Path) -> None:
        """Windows ships 32-bit IFEO tuning with no Debugger, so nothing fires."""
        tree = make_node(
            children={
                "iexplore.exe": make_node(
                    name="iexplore.exe",
                    values={"MitigationOptions": 256, "CFGOptions": 1},
                ),
                "ExtExport.exe": make_node(
                    name="ExtExport.exe",
                    values={"DisableExceptionChainValidation": 0},
                ),
            }
        )
        plugin = make_plugin(IfeoDebugger, tmp_path)
        _wire_key(plugin, _WOW64_IFEO_KEY, tree)
        assert plugin.run() == []

    def test_both_views_reported_independently(self, tmp_path: Path) -> None:
        """Each view is a distinct key, so a hijack in either is its own finding."""
        native = make_node(
            children={
                "a.exe": make_node(name="a.exe", values={"Debugger": "bad64.exe"})
            }
        )
        redirected = make_node(
            children={
                "b.exe": make_node(name="b.exe", values={"Debugger": "bad32.exe"})
            }
        )
        plugin = make_plugin(IfeoDebugger, tmp_path)
        setup_keys(plugin, {_IFEO_KEY: native, _WOW64_IFEO_KEY: redirected})
        paths = [finding.path for finding in plugin.run()]
        assert len(paths) == 2
        assert paths[0].startswith(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        )
        assert paths[1].startswith("HKLM\\SOFTWARE\\Wow6432Node\\Microsoft")

    def test_ignores_undeclared_key(self, tmp_path: Path) -> None:
        """A Debugger under another key must not be picked up by this check."""
        image_key = make_node(name="notepad.exe", values={"Debugger": "evil.exe"})
        tree = make_node(children={"notepad.exe": image_key})
        plugin = make_plugin(IfeoDebugger, tmp_path)
        setup_keys(plugin, {r"Microsoft\Windows NT\CurrentVersion\Winlogon": tree})
        assert plugin.run() == []


class TestIfeoSilentProcessExit:
    """Cases for SilentProcessExit, which runs a monitor when a process ends."""

    def test_happy_path(self, tmp_path: Path) -> None:
        """MonitorProcess gives execution on process exit, which is persistence."""
        image_key = make_node(
            name="calc.exe", values={"MonitorProcess": "backdoor.exe"}
        )
        tree = make_node(children={"calc.exe": image_key})
        plugin = make_plugin(IfeoSilentProcessExit, tmp_path)
        _wire_key(plugin, _SPE_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert "backdoor.exe" in findings[0].value
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert findings[0].path == (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\SilentProcessExit\\calc.exe\\MonitorProcess"
        )

    def test_no_monitor_process(self, tmp_path: Path) -> None:
        """SilentProcessExit keys exist on clean hosts; only the monitor matters."""
        image_key = make_node(name="calc.exe", values={"Other": "val"})
        tree = make_node(children={"calc.exe": image_key})
        plugin = make_plugin(IfeoSilentProcessExit, tmp_path)
        _wire_key(plugin, _SPE_KEY, tree)
        assert plugin.run() == []

    def test_monitor_process_in_nested_subkey(self, tmp_path: Path) -> None:
        """A monitor parked in a nested subkey is found rather than skipped."""
        nested = make_node(name="{f1}", values={"MonitorProcess": "backdoor.exe"})
        image_key = make_node(
            name="calc.exe", values={"ReportingMode": 1}, children={"{f1}": nested}
        )
        tree = make_node(children={"calc.exe": image_key})
        plugin = make_plugin(IfeoSilentProcessExit, tmp_path)
        _wire_key(plugin, _SPE_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path.endswith(
            "\\SilentProcessExit\\calc.exe\\{f1}\\MonitorProcess"
        )

    def test_nested_reporting_config_stays_quiet(self, tmp_path: Path) -> None:
        """Nested SilentProcessExit tuning without a monitor is not persistence."""
        nested = make_node(
            name="{f1}", values={"DumpFolder": "C:\\Dumps", "DumpType": 2}
        )
        image_key = make_node(
            name="calc.exe", values={"ReportingMode": 1}, children={"{f1}": nested}
        )
        tree = make_node(children={"calc.exe": image_key})
        plugin = make_plugin(IfeoSilentProcessExit, tmp_path)
        _wire_key(plugin, _SPE_KEY, tree)
        assert plugin.run() == []

    def test_monitor_process_in_wow6432node_view(self, tmp_path: Path) -> None:
        """A 32-bit process registers its monitor through the redirector."""
        image_key = make_node(
            name="legacy32.exe", values={"MonitorProcess": "backdoor32.exe"}
        )
        tree = make_node(children={"legacy32.exe": image_key})
        plugin = make_plugin(IfeoSilentProcessExit, tmp_path)
        _wire_key(plugin, _WOW64_SPE_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "backdoor32.exe"
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert findings[0].path == (
            "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT"
            "\\CurrentVersion\\SilentProcessExit"
            "\\legacy32.exe\\MonitorProcess"
        )

    def test_wow6432node_reporting_config_stays_quiet(self, tmp_path: Path) -> None:
        """Dump tuning in the 32-bit view carries no monitor, so nothing fires."""
        image_key = make_node(
            name="legacy32.exe",
            values={"ReportingMode": 2, "DumpFolder": "C:\\Dumps"},
        )
        tree = make_node(children={"legacy32.exe": image_key})
        plugin = make_plugin(IfeoSilentProcessExit, tmp_path)
        _wire_key(plugin, _WOW64_SPE_KEY, tree)
        assert plugin.run() == []


class TestIfeoDelegatedNtdll:
    """Cases for VerifierDlls, which injects a DLL into every start of an image."""

    def test_happy_path_flag_0x100(self, tmp_path: Path) -> None:
        """A DWORD GlobalFlag arming Application Verifier is the classic form."""
        image_key = make_node(
            name="target.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": 0x100},
        )
        tree = make_node(children={"target.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "evil.dll"
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert findings[0].path == (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            "\\Image File Execution Options\\target.exe\\VerifierDlls"
        )

    def test_globalflag_combined_bits(self, tmp_path: Path) -> None:
        """A 0x100 bit set among other GlobalFlag bits still arms the verifier."""
        image_key = make_node(
            name="target.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": 0x300},
        )
        tree = make_node(children={"target.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        assert len(plugin.run()) == 1

    def test_globalflag_written_as_string(self, tmp_path: Path) -> None:
        """The loader accepts a REG_SZ GlobalFlag, so a string must not hide it."""
        image_key = make_node(
            name="explorer.exe",
            values={"VerifierDlls": "evil.dll", "GlobalFlag": "0x100"},
        )
        tree = make_node(children={"explorer.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "evil.dll"

    def test_verifier_dlls_without_globalflag(self, tmp_path: Path) -> None:
        """A VerifierDlls list is the technique; GlobalFlag need not corroborate."""
        image_key = make_node(name="target.exe", values={"VerifierDlls": "evil.dll"})
        tree = make_node(children={"target.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "evil.dll"

    def test_verifier_dlls_in_filter_subkey(self, tmp_path: Path) -> None:
        """A filter subkey scopes the injection to one image path, not hides it."""
        filter_key = make_node(
            name="{f1}",
            values={
                "FilterFullPath": "C:\\Windows\\explorer.exe",
                "VerifierDlls": "evil.dll",
                "GlobalFlag": "0x100",
            },
        )
        image_key = make_node(
            name="explorer.exe",
            values={"UseFilter": 1},
            children={"{f1}": filter_key},
        )
        tree = make_node(children={"explorer.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].path.endswith(
            "\\Image File Execution Options\\explorer.exe\\{f1}\\VerifierDlls"
        )

    def test_no_verifier_dlls(self, tmp_path: Path) -> None:
        """GlobalFlag alone is a debugging setting with nothing to load."""
        image_key = make_node(name="target.exe", values={"GlobalFlag": 0x100})
        tree = make_node(children={"target.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        assert plugin.run() == []

    def test_mitigation_only_entries_stay_quiet(self, tmp_path: Path) -> None:
        """Windows ships IFEO keys full of mitigation tuning and no VerifierDlls."""
        tree = make_node(
            children={
                "iexplore.exe": make_node(
                    name="iexplore.exe",
                    values={
                        "MitigationOptions": 256,
                        "DisableUserModeCallbackFilter": 1,
                    },
                ),
                "svchost.exe": make_node(
                    name="svchost.exe", values={"MinimumStackCommitInBytes": 32768}
                ),
            }
        )
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _IFEO_KEY, tree)
        assert plugin.run() == []

    def test_verifier_dlls_in_wow6432node_view(self, tmp_path: Path) -> None:
        """Injection into a 32-bit image is configured in the redirected view."""
        image_key = make_node(
            name="legacy32.exe",
            values={"VerifierDlls": "evil32.dll", "GlobalFlag": 0x100},
        )
        tree = make_node(children={"legacy32.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _WOW64_IFEO_KEY, tree)
        findings = plugin.run()
        assert len(findings) == 1
        assert findings[0].value == "evil32.dll"
        assert findings[0].access_gained == AccessLevel.SYSTEM
        assert findings[0].path == (
            "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT"
            "\\CurrentVersion\\Image File Execution Options"
            "\\legacy32.exe\\VerifierDlls"
        )

    def test_wow6432node_mitigation_only_stays_quiet(self, tmp_path: Path) -> None:
        """The shipped 32-bit IFEO entries carry no VerifierDlls, so stay quiet."""
        tree = make_node(
            children={
                "ielowutil.exe": make_node(
                    name="ielowutil.exe", values={"MitigationOptions": 256}
                ),
                "msfeedssync.exe": make_node(
                    name="msfeedssync.exe", values={"ImageExpansionMitigation": 0}
                ),
            }
        )
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        _wire_key(plugin, _WOW64_IFEO_KEY, tree)
        assert plugin.run() == []

    def test_ignores_undeclared_key(self, tmp_path: Path) -> None:
        """VerifierDlls elsewhere in the hive is not this check's business."""
        image_key = make_node(name="target.exe", values={"VerifierDlls": "evil.dll"})
        tree = make_node(children={"target.exe": image_key})
        plugin = make_plugin(IfeoDelegatedNtdll, tmp_path)
        setup_keys(plugin, {r"Microsoft\Windows NT\CurrentVersion\Winlogon": tree})
        assert plugin.run() == []
