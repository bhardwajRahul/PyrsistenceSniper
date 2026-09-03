"""Tests for the triage enrichment that summarizes resolution facts."""

from __future__ import annotations

import dataclasses

from pyrsistencesniper.core.models import AccessLevel, Finding
from pyrsistencesniper.enrichment.triage import TriageEnrichment


def _finding(**overrides: object) -> Finding:
    """Build a Run-key finding whose resolution facts are unset until overridden."""
    base = Finding(
        path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        value="C:\\temp\\evil.exe",
        technique="Registry Run Key",
        mitre_id="T1547.001",
        access_gained=AccessLevel.SYSTEM,
        check_id="run_keys",
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


def _notes(finding: Finding) -> str:
    """Return the triage notes, or an empty string when the enrichment declines."""
    enrichment = TriageEnrichment().enrich(finding)
    return "" if enrichment is None else enrichment.data["notes"]


def test_unresolved_finding_produces_no_notes() -> None:
    """A finding whose target was never resolved carries no triage claims."""
    assert TriageEnrichment().enrich(_finding()) is None


def test_missing_binary_is_flagged() -> None:
    """A resolved target that is absent from the image is called out."""
    assert "not found at the resolved path" in _notes(_finding(exists=False))


def test_lolbin_is_flagged() -> None:
    """A living off the land binary is called out regardless of resolution."""
    assert "living off the land" in _notes(_finding(is_lolbin=True))


def test_present_unsigned_binary_is_flagged() -> None:
    """A present binary with no signature prompts a hash comparison."""
    notes = _notes(_finding(exists=True, signer="", is_in_os_directory=True))
    assert "no usable signature" in notes


def test_present_signed_binary_in_os_directory_is_quiet() -> None:
    """A signed binary inside the OS directories needs no triage note."""
    finding = _finding(exists=True, signer="Microsoft Windows", is_in_os_directory=True)
    assert TriageEnrichment().enrich(finding) is None


def test_binary_outside_os_directory_is_flagged() -> None:
    """A present binary running from outside the OS directories is called out."""
    notes = _notes(
        _finding(exists=True, signer="Contoso Ltd", is_in_os_directory=False)
    )
    assert "outside the OS directories" in notes


def test_missing_binary_does_not_claim_signature_facts() -> None:
    """An absent binary must not produce signature or location claims."""
    notes = _notes(_finding(exists=False, signer=""))
    assert "signature" not in notes


def test_provider_is_named_triage() -> None:
    """The enrichment identifies itself so its output column is stable."""
    enrichment = TriageEnrichment().enrich(_finding(exists=False))
    assert enrichment is not None
    assert enrichment.provider == "triage"
