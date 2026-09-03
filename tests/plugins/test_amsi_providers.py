"""Tests for AmsiProviders CLSID enumeration plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import AccessLevel, Finding, Severity
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.plugins.T1546.amsi_providers import AmsiProviders

from .conftest import make_node, make_plugin, setup_keys

if TYPE_CHECKING:
    from pathlib import Path

_CLSID = "{2781761E-28E0-4109-99FE-B9D127C57AFE}"
_PROVIDERS_KEY = r"Microsoft\AMSI\Providers"


def _providers_tree(clsid: str) -> object:
    """Build the AMSI Providers key holding one provider registration."""
    return make_node(children={clsid: make_node(name=clsid)})


def _classify(finding: Finding) -> Severity:
    """Classify a finding with the shipped profile, as a real scan would."""
    return DetectionProfile.load(None).policy_for("amsi_providers").classify(finding)


def test_provider_with_native_com_server(tmp_path: Path) -> None:
    """An AMSI provider CLSID with an InprocServer32 DLL produces a finding."""
    plugin = make_plugin(AmsiProviders, tmp_path)
    setup_keys(
        plugin,
        {
            _PROVIDERS_KEY: _providers_tree(_CLSID),
            rf"Classes\CLSID\{_CLSID}\InprocServer32": make_node(
                values={"(Default)": r"C:\evil_amsi.dll"}
            ),
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].path == rf"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{_CLSID}"
    assert findings[0].value == r"C:\evil_amsi.dll"
    assert findings[0].access_gained is AccessLevel.SYSTEM


def test_provider_registered_in_the_32_bit_view(tmp_path: Path) -> None:
    """A 32-bit COM server lands under Wow6432Node, where the DLL is still named."""
    plugin = make_plugin(AmsiProviders, tmp_path)
    setup_keys(
        plugin,
        {
            _PROVIDERS_KEY: _providers_tree(_CLSID),
            rf"Classes\Wow6432Node\CLSID\{_CLSID}\InprocServer32": make_node(
                values={"(Default)": r"C:\ProgramData\amsi.dll"}
            ),
        },
    )

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == r"C:\ProgramData\amsi.dll"


def test_provider_without_com_server_is_still_reported(tmp_path: Path) -> None:
    """An unresolvable CLSID is the easiest state to reach, so it must not vanish."""
    plugin = make_plugin(AmsiProviders, tmp_path)
    setup_keys(plugin, {_PROVIDERS_KEY: _providers_tree(_CLSID)})

    findings = plugin.run()

    assert len(findings) == 1
    assert findings[0].value == _CLSID
    assert "no InprocServer32" in findings[0].description


def test_defender_provider_stays_quiet_in_the_profile() -> None:
    """The one provider a clean install ships is suppressed by the profile."""
    finding = Finding(
        path=rf"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{_CLSID}",
        value=(
            r"C:\ProgramData\Microsoft\Windows Defender"
            r"\Platform\4.18.26080.3-0\MpOav.dll"
        ),
        check_id="amsi_providers",
        signer="Microsoft",
    )

    assert _classify(finding) < Severity.MEDIUM


def test_unresolvable_provider_reaches_medium() -> None:
    """A provider naming no DLL is anomalous on its own and must be reported."""
    finding = Finding(
        path=r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{8f6d5a1e-0000-0000-0000-0}",
        value="{8f6d5a1e-0000-0000-0000-0}",
        check_id="amsi_providers",
    )

    assert _classify(finding) >= Severity.MEDIUM


def test_no_hive_returns_empty(tmp_path: Path) -> None:
    """A missing SOFTWARE hive is a clean absence, not a scan failure."""
    plugin = make_plugin(AmsiProviders, tmp_path)
    plugin.context.hive_path.return_value = None
    plugin.registry.open_hive.return_value = None

    assert plugin.run() == []


def test_no_providers_key_returns_empty(tmp_path: Path) -> None:
    """A host with no AMSI Providers key registers no providers at all."""
    plugin = make_plugin(AmsiProviders, tmp_path)
    setup_keys(plugin, {})

    assert plugin.run() == []
