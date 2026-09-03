"""Detection for Active Setup."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_ACTIVE_SETUP_PATHS = (
    r"Microsoft\Active Setup\Installed Components",
    r"Wow6432Node\Microsoft\Active Setup\Installed Components",
)

# StubPath values that are bare flags rather than executable commands.
_STUB_FLAGS: frozenset[str] = frozenset(
    {
        "/UserInstall",
        "U",
    }
)


@register_plugin
class ActiveSetup(PersistencePlugin):
    """Detects Active Setup persistence entries."""

    definition = CheckDefinition(
        id="active_setup",
        technique="Active Setup",
        mitre_id="T1547.014",
        description=(
            "Active Setup StubPath commands run once per user at first "
            "logon. Adversaries register components under Installed "
            "Components to achieve per-user persistence with SYSTEM-level "
            "registry access. The 32-bit component list under Wow6432Node "
            "is processed independently and is checked as well."
        ),
        references=("https://attack.mitre.org/techniques/T1547/014/",),
    )

    def run(self) -> list[Finding]:
        """Report every Installed Components StubPath that runs a command."""
        findings: list[Finding] = []

        for key_path in _ACTIVE_SETUP_PATHS:
            tree = self.context.load_subtree("SOFTWARE", key_path)
            if tree is None:
                continue

            for component, node in tree.children():
                value_str = registry_value_to_str(node.get("StubPath"))
                if value_str is None or value_str in _STUB_FLAGS:
                    continue

                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SOFTWARE\\{key_path}\\{component}\\StubPath",
                        value=value_str,
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
