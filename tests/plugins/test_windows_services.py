"""Tests for the service ImagePath and ServiceDll checks (T1543.003)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import AccessLevel, Finding, MatchResult, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1543.windows_services import (
    WindowsServiceDll,
    WindowsServiceImagePath,
)

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_SERVICES_KEY = r"ControlSet001\Services"


class TestWindowsServiceImagePath:
    """Cases for ImagePath, which names the binary the service actually runs."""

    def test_happy_path(self, tmp_path: Path) -> None:
        """ImagePath names the binary the Service Control Manager launches as SYSTEM."""
        child = make_node(name="Svc", values={"ImagePath": "C:\\svc.exe"})
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_keys(plugin, {_SERVICES_KEY: make_node(children={"Svc": child})})

        findings = plugin.run()
        assert len(findings) == 1
        finding = findings[0]
        assert "svc.exe" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1543" in finding.mitre_id
        assert finding.path == (r"HKLM\SYSTEM\ControlSet001\Services\Svc\ImagePath")

    def test_driver_service_without_image_path_is_reported(
        self, tmp_path: Path
    ) -> None:
        """A kernel driver service that omits ImagePath still boot-loads its .sys."""
        child = make_node(
            name="wdfilter2", values={"Type": 1, "Start": 0, "ErrorControl": 1}
        )
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_keys(plugin, {_SERVICES_KEY: make_node(children={"wdfilter2": child})})

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.value == "wdfilter2.sys"
        assert finding.path == r"HKLM\SYSTEM\ControlSet001\Services\wdfilter2"
        assert finding.resolve_target == (r"\SystemRoot\System32\drivers\wdfilter2.sys")
        assert finding.access_gained == AccessLevel.SYSTEM

    @pytest.mark.parametrize(
        "service_type",
        [1, 2, 8, "2", "0x2"],
        ids=["kernel", "filesystem", "recognizer", "string_type", "hex_string_type"],
    )
    def test_every_driver_type_without_image_path_is_reported(
        self, tmp_path: Path, service_type: object
    ) -> None:
        """Kernel, filesystem and recognizer drivers all load by key-name convention."""
        child = make_node(name="drv", values={"Type": service_type})
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_keys(plugin, {_SERVICES_KEY: make_node(children={"drv": child})})

        findings = plugin.run()

        assert len(findings) == 1
        assert findings[0].value == "drv.sys"

    def test_non_service_subkey_without_image_path_stays_quiet(
        self, tmp_path: Path
    ) -> None:
        """A Services subkey carrying no Type is not a service and is not reported."""
        child = make_node(name="PerfOS", values={"Description": "Some counters"})
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_keys(plugin, {_SERVICES_KEY: make_node(children={"PerfOS": child})})

        assert plugin.run() == []

    def test_user_mode_service_without_image_path_stays_quiet(
        self, tmp_path: Path
    ) -> None:
        """The drivers directory convention is kernel-only, so Win32 types skip."""
        child = make_node(name="Win32Svc", values={"Type": 16, "Start": 2})
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_keys(plugin, {_SERVICES_KEY: make_node(children={"Win32Svc": child})})

        assert plugin.run() == []

    def test_unreadable_service_type_stays_quiet(self, tmp_path: Path) -> None:
        """A Type that is not a number is not evidence of a driver and is skipped."""
        child = make_node(name="Odd", values={"Type": "kernel"})
        plugin = make_plugin(WindowsServiceImagePath, tmp_path)
        setup_keys(plugin, {_SERVICES_KEY: make_node(children={"Odd": child})})

        assert plugin.run() == []


class TestWindowsServiceDll:
    """Cases for ServiceDll, which sits one level down under Parameters."""

    def test_happy_path_nested_parameters(self, tmp_path: Path) -> None:
        """ServiceDll names the DLL a shared svchost process loads for the service."""
        parameters_node = make_node(
            name="Parameters", values={"ServiceDll": "C:\\evil.dll"}
        )
        service_node = make_node(
            name="svchost_svc", children={"Parameters": parameters_node}
        )
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_keys(
            plugin, {_SERVICES_KEY: make_node(children={"svchost_svc": service_node})}
        )

        findings = plugin.run()
        assert len(findings) == 1
        finding = findings[0]
        assert "evil.dll" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "T1543" in finding.mitre_id
        assert finding.path == (
            r"HKLM\SYSTEM\ControlSet001\Services"
            r"\svchost_svc\Parameters\ServiceDll"
        )

    def test_service_without_parameters_subkey(self, tmp_path: Path) -> None:
        """A service with no Parameters subkey registers no ServiceDll to load."""
        service_node = make_node(name="PlainSvc", values={"ImagePath": "C:\\svc.exe"})
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_keys(
            plugin, {_SERVICES_KEY: make_node(children={"PlainSvc": service_node})}
        )

        assert plugin.run() == []

    def test_parameters_without_service_dll(self, tmp_path: Path) -> None:
        """A Parameters subkey is ordinary service configuration on its own."""
        parameters_node = make_node(
            name="Parameters", values={"SomeOtherValue": "data"}
        )
        service_node = make_node(
            name="SvcWithParams", children={"Parameters": parameters_node}
        )
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_keys(
            plugin, {_SERVICES_KEY: make_node(children={"SvcWithParams": service_node})}
        )

        assert plugin.run() == []

    def test_multiple_services_mixed(self, tmp_path: Path) -> None:
        """One service registering a ServiceDll does not implicate its neighbours."""
        parameters_a = make_node(name="Parameters", values={"ServiceDll": "C:\\a.dll"})
        service_a = make_node(name="SvcA", children={"Parameters": parameters_a})
        service_b = make_node(name="SvcB", values={"ImagePath": "C:\\b.exe"})
        plugin = make_plugin(WindowsServiceDll, tmp_path)
        setup_keys(
            plugin,
            {_SERVICES_KEY: make_node(children={"SvcA": service_a, "SvcB": service_b})},
        )

        findings = plugin.run()
        assert len(findings) == 1
        assert "a.dll" in findings[0].value


class TestMsiexecFilterRule:
    """Cases for the profile rule that allows a signed msiexec and nothing else."""

    rule = next(
        allow_rule
        for allow_rule in DetectionProfile.load(None)
        .policy_for("windows_service_image_path")
        .allow
        if "msiexec" in allow_rule.value_matches
    )

    @pytest.mark.parametrize(
        ("value", "signer", "expected"),
        [
            (r"msiexec.exe /V", "Microsoft Windows", MatchResult.FULL),
            (r"msiexec.exe /V", "", MatchResult.PARTIAL),
            (r"C:\evil.exe", "Microsoft Windows", MatchResult.NONE),
        ],
        ids=["signed_full", "unsigned_partial", "non_msiexec_none"],
    )
    def test_match_result(self, value: str, signer: str, expected: MatchResult) -> None:
        """Signed msiexec is FULL, unsigned degrades to PARTIAL, non-msiexec is NONE."""
        finding = Finding(value=value, signer=signer)
        assert self.rule.match_result(finding) == expected


class TestImpliedDriverValueShape:
    """The bare .sys value must not be swallowed by the built-in system32 rule."""

    policy = DetectionProfile.load(None).policy_for("windows_service_image_path")

    def test_unsigned_implied_driver_reaches_medium(self) -> None:
        """An unsigned driver named only by its key stays reportable by default."""
        finding = Finding(
            path=r"HKLM\SYSTEM\ControlSet001\Services\wdfilter2",
            value="wdfilter2.sys",
            check_id="windows_service_image_path",
            signer="",
            is_lolbin=False,
        )

        assert self.policy.classify(finding) >= Severity.MEDIUM

    def test_a_full_system32_driver_path_would_have_been_degraded(self) -> None:
        """Emitting the resolved path instead would hide the driver below MEDIUM."""
        finding = Finding(
            path=r"HKLM\SYSTEM\ControlSet001\Services\wdfilter2",
            value=r"\SystemRoot\System32\drivers\wdfilter2.sys",
            check_id="windows_service_image_path",
            signer="",
            is_lolbin=False,
        )

        assert self.policy.classify(finding) < Severity.MEDIUM
