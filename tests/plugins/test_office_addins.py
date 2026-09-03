"""Tests for the OfficeAddins and OfficeAiHijack plugins (T1137.006)."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.models import AccessLevel
from pyrsistencesniper.plugins.T1137.office_addins import OfficeAddins, OfficeAiHijack

from .conftest import make_node, make_plugin, make_user_profiles, setup_hklm, setup_keys

_HKLM_ADDINS_KEY = r"Microsoft\Office\Word\Addins"
_HKU_ADDINS_KEY = r"Software\Microsoft\Office\Word\Addins"
_ADDIN_CLSID = "{11111111-2222-3333-4444-555566667777}"
_PAYLOAD_DLL = r"C:\ProgramData\upd.dll"


class TestOfficeAddins:
    """Cases for add-ins, which register both per machine and per user."""

    def test_hklm_addin_manifest_produces_finding(self, tmp_path: Path) -> None:
        """A Manifest on the machine Addins key loads for every user of that host."""
        addin_node = make_node(
            name="EvilAddin", values={"Manifest": "C:\\evil.manifest"}
        )
        plugin = make_plugin(OfficeAddins, tmp_path)
        setup_keys(
            plugin, {_HKLM_ADDINS_KEY: make_node(children={"EvilAddin": addin_node})}
        )

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.path == (
            r"HKLM\SOFTWARE\Microsoft\Office\Word\Addins\EvilAddin\Manifest"
        )
        assert "evil.manifest" in finding.value
        assert finding.access_gained == AccessLevel.SYSTEM
        assert finding.mitre_id == "T1137.006"

    def test_hklm_com_addin_resolves_inprocserver_dll(self, tmp_path: Path) -> None:
        """A COM add-in carrying only LoadBehavior is followed to its DLL."""
        addin_node = make_node(
            name="Updater.Connect",
            values={
                "FriendlyName": "Office Updater",
                "Description": "Keeps Office up to date",
                "LoadBehavior": 3,
            },
        )
        plugin = make_plugin(OfficeAddins, tmp_path)
        setup_keys(
            plugin,
            {
                _HKLM_ADDINS_KEY: make_node(children={"Updater.Connect": addin_node}),
                r"Classes\Updater.Connect\CLSID": make_node(
                    values={"(Default)": _ADDIN_CLSID}
                ),
                rf"Classes\CLSID\{_ADDIN_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _PAYLOAD_DLL}
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.path == (
            r"HKLM\SOFTWARE\Microsoft\Office\Word\Addins\Updater.Connect"
        )
        assert finding.value == _PAYLOAD_DLL
        assert finding.access_gained == AccessLevel.SYSTEM
        assert "LoadBehavior: 3 (loads automatically at application startup)" in (
            finding.description
        )
        assert _ADDIN_CLSID in finding.description

    def test_hku_com_addin_resolves_usrclass_registration(self, tmp_path: Path) -> None:
        """A per-user COM add-in is followed through the user's UsrClass hive."""
        addin_node = make_node(
            name="Updater.Connect",
            values={"FriendlyName": "Office Updater", "LoadBehavior": 3},
        )
        plugin = make_plugin(
            OfficeAddins, tmp_path, user_profiles=make_user_profiles("alice")
        )
        setup_keys(
            plugin,
            {
                _HKU_ADDINS_KEY: make_node(children={"Updater.Connect": addin_node}),
                r"Updater.Connect\CLSID": make_node(values={"(Default)": _ADDIN_CLSID}),
                rf"CLSID\{_ADDIN_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _PAYLOAD_DLL}
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.path == (
            r"HKU\alice\Software\Microsoft\Office\Word\Addins\Updater.Connect"
        )
        assert finding.value == _PAYLOAD_DLL
        assert finding.access_gained is AccessLevel.USER

    def test_disabled_com_addin_is_reported_as_disabled(self, tmp_path: Path) -> None:
        """A LoadBehavior 0 add-in still fires but says it is not loaded."""
        addin_node = make_node(name="Updater.Connect", values={"LoadBehavior": 0})
        plugin = make_plugin(OfficeAddins, tmp_path)
        setup_keys(
            plugin,
            {
                _HKLM_ADDINS_KEY: make_node(children={"Updater.Connect": addin_node}),
                r"Classes\Updater.Connect\CLSID": make_node(
                    values={"(Default)": _ADDIN_CLSID}
                ),
                rf"Classes\CLSID\{_ADDIN_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _PAYLOAD_DLL}
                ),
            },
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert "LoadBehavior: 0 (registered but not loaded)" in (
            findings[0].description
        )

    def test_addin_key_without_com_registration_stays_quiet(
        self, tmp_path: Path
    ) -> None:
        """A leftover add-in key whose ProgID resolves nowhere yields nothing."""
        addin_node = make_node(
            name="Uninstalled.Connect",
            values={"FriendlyName": "Removed add-in", "LoadBehavior": 3},
        )
        plugin = make_plugin(OfficeAddins, tmp_path)
        setup_keys(
            plugin,
            {_HKLM_ADDINS_KEY: make_node(children={"Uninstalled.Connect": addin_node})},
        )

        assert plugin.run() == []

    def test_addin_key_without_load_behavior_stays_quiet(self, tmp_path: Path) -> None:
        """A key with no LoadBehavior is not a load point, so nothing is emitted."""
        addin_node = make_node(name="SomeAddin", values={"FriendlyName": "Some add-in"})
        plugin = make_plugin(OfficeAddins, tmp_path)
        setup_keys(
            plugin,
            {
                _HKLM_ADDINS_KEY: make_node(children={"SomeAddin": addin_node}),
                r"Classes\SomeAddin\CLSID": make_node(
                    values={"(Default)": _ADDIN_CLSID}
                ),
                rf"Classes\CLSID\{_ADDIN_CLSID}\InprocServer32": make_node(
                    values={"(Default)": _PAYLOAD_DLL}
                ),
            },
        )

        assert plugin.run() == []

    def test_hku_addin_produces_user_finding(self, tmp_path: Path) -> None:
        """A per-user add-in loads only into that profile's Office processes."""
        addin_node = make_node(name="UserAddin", values={"FileName": "C:\\addin.dll"})
        plugin = make_plugin(
            OfficeAddins, tmp_path, user_profiles=make_user_profiles("bob")
        )
        setup_keys(
            plugin, {_HKU_ADDINS_KEY: make_node(children={"UserAddin": addin_node})}
        )

        findings = plugin.run()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.path == (
            r"HKU\bob\Software\Microsoft\Office\Word\Addins\UserAddin\FileName"
        )
        assert "addin.dll" in finding.value
        assert finding.access_gained == AccessLevel.USER


class TestOfficeAiHijack:
    """Cases for the Office AI key, a separate and newer registration point."""

    def test_ai_value_produces_finding(self, tmp_path: Path) -> None:
        """Any value under the AI key is a load path, so none is filtered out."""
        tree = make_node(values={"SomeFeature": "{evil-clsid}"})
        plugin = make_plugin(OfficeAiHijack, tmp_path)
        setup_hklm(
            plugin,
            tree,
            key_path=(
                r"Microsoft\Office\ClickToRun\REGISTRY\MACHINE"
                r"\Software\Microsoft\Office\16.0\Common\AI"
            ),
        )

        findings = plugin.run()

        assert len(findings) == 1
        assert "evil-clsid" in findings[0].value
