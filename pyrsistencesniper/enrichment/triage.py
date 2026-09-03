"""Triage enrichment that states why a finding deserves an analyst's attention."""

from __future__ import annotations

from pyrsistencesniper.core.models import Enrichment, Finding
from pyrsistencesniper.enrichment.base import EnrichmentPlugin, register_enrichment

_MISSING_TARGET = "Referenced binary was not found at the resolved path"
_LOLBIN = "Target is a living off the land binary abused to proxy execution"
_UNSIGNED = "Binary carries no usable signature; compare its hash against known good"
_OUTSIDE_OS = "Binary runs from outside the OS directories"


@register_enrichment
class TriageEnrichment(EnrichmentPlugin):
    """Summarize the resolution facts a defender would otherwise derive by hand."""

    provider = "triage"

    def enrich(self, finding: Finding) -> Enrichment | None:
        """Return short triage notes, or None when nothing is worth flagging."""
        notes = list(self._notes(finding))
        if not notes:
            return None
        return Enrichment(provider=self.provider, data={"notes": "; ".join(notes)})

    @staticmethod
    def _notes(finding: Finding) -> list[str]:
        """Collect the triage notes that apply to a single finding."""
        notes: list[str] = []
        if finding.is_lolbin:
            notes.append(_LOLBIN)
        if finding.exists is False:
            notes.append(_MISSING_TARGET)
        elif finding.exists is True:
            if not finding.signer:
                notes.append(_UNSIGNED)
            if finding.is_in_os_directory is False:
                notes.append(_OUTSIDE_OS)
        return notes
