"""Detection for .NET Framework COR_PROFILER Registry Key."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class DotNetFrameworkProfiler(PersistencePlugin):
    """Detects .NET Framework COR_PROFILER Registry Key persistence entries."""

    definition = CheckDefinition(
        id="dotnet_framework_profiler",
        technique=".NET Framework COR_PROFILER Registry Key",
        mitre_id="T1574.012",
        description=(
            "COR_PROFILER, COR_PROFILER_PATH, and COR_ENABLE_PROFILING "
            "values in the .NETFramework registry key cause the CLR to "
            "load a custom profiler DLL into every managed process. "
            "The per-user and WoW64 copies of the key are checked too; "
            "the per-user one needs no administrative rights. "
            "Profiling is rarely enabled in production environments."
        ),
        references=("https://attack.mitre.org/techniques/T1574/012/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_PROFILER",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_PROFILER_PATH",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="COR_ENABLE_PROFILING",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
        ),
    )
