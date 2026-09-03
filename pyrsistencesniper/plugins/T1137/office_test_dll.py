"""Detect Office Test DLL persistence (T1137.002)."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class OfficeTestDll(PersistencePlugin):
    """Detects Office Test DLL persistence entries."""

    definition = CheckDefinition(
        id="office_test_dll",
        technique="Office Test DLL",
        mitre_id="T1137.002",
        description=(
            "The undocumented Office Test\\Special\\Perf key specifies a "
            "DLL loaded by Office applications at startup. Any value "
            "present indicates persistence, as this key has no legitimate "
            "use. 32-bit Office reads the WoW64 copy of the key, so both "
            "registry views are checked."
        ),
        references=("https://attack.mitre.org/techniques/T1137/002/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Office Test\Special\Perf",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
        ),
    )
