"""Tests for the enrichment runner: error isolation and result collection."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pyrsistencesniper.core.models import AccessLevel, Enrichment, Finding
from pyrsistencesniper.enrichment import base as enrichment_base
from pyrsistencesniper.enrichment.base import EnrichmentPlugin, run_enrichments


def _make_finding(value: str = "test.exe") -> Finding:
    """Build a minimal Finding; only the value distinguishes one from another."""
    return Finding(
        path="HKLM\\Run",
        value=value,
        technique="Test",
        mitre_id="T0000",
        description="d",
        access_gained=AccessLevel.SYSTEM,
        hostname="HOST",
        check_id="test_check",
    )


class _GoodPlugin(EnrichmentPlugin):
    """Provider that has data for every finding."""

    def enrich(self, finding: Finding) -> Enrichment | None:
        """Return a fixed enrichment so results are predictable."""
        return Enrichment(provider="good", data={"score": "10"})


class _NonePlugin(EnrichmentPlugin):
    """Provider with nothing to say about any finding."""

    def enrich(self, finding: Finding) -> Enrichment | None:
        """Return None, the contract's way of contributing nothing."""
        return None


class _CrashingPlugin(EnrichmentPlugin):
    """Provider that raises, to prove one bad plugin cannot sink a scan."""

    def enrich(self, finding: Finding) -> Enrichment | None:
        """Always raise; the runner is expected to log and continue."""
        raise RuntimeError("plugin exploded")


_RegistryInstaller = Callable[..., None]


@pytest.fixture
def only_registered(monkeypatch: pytest.MonkeyPatch) -> _RegistryInstaller:
    """Replace the enrichment registry with an explicit list for one test."""

    def _install(*plugins: type[EnrichmentPlugin]) -> None:
        """Swap the module-level registry for exactly these plugin classes."""
        monkeypatch.setattr(enrichment_base, "_ENRICHMENT_REGISTRY", list(plugins))

    return _install


def test_run_enrichments_collects_results(only_registered: _RegistryInstaller) -> None:
    """run_enrichments pairs each finding with the enrichments produced for it."""
    only_registered(_GoodPlugin)

    results = run_enrichments([_make_finding("a.exe"), _make_finding("b.exe")])

    assert [enrichments[0].provider for _finding, enrichments in results] == [
        "good",
        "good",
    ]


def test_run_enrichments_preserves_finding_order(
    only_registered: _RegistryInstaller,
) -> None:
    """Results come back in the order the findings were supplied."""
    only_registered(_GoodPlugin)

    results = run_enrichments([_make_finding("a.exe"), _make_finding("b.exe")])

    assert [finding.value for finding, _enrichments in results] == ["a.exe", "b.exe"]


def test_run_enrichments_skips_none(only_registered: _RegistryInstaller) -> None:
    """An enrichment returning None contributes nothing to the result tuple."""
    only_registered(_NonePlugin)

    results = run_enrichments([_make_finding()])

    assert results[0][1] == ()


def test_run_enrichments_isolates_crash(only_registered: _RegistryInstaller) -> None:
    """A crashing enrichment does not prevent the others from running."""
    only_registered(_CrashingPlugin, _GoodPlugin)

    results = run_enrichments([_make_finding()])

    assert [enrichment.provider for enrichment in results[0][1]] == ["good"]


def test_run_enrichments_reports_progress(only_registered: _RegistryInstaller) -> None:
    """The runner reports one progress tick per finding."""
    only_registered(_GoodPlugin)
    calls: list[tuple[str, int, int]] = []

    run_enrichments(
        [_make_finding("a.exe"), _make_finding("b.exe")],
        progress=lambda stage, current, total: calls.append((stage, current, total)),
    )

    assert calls == [("Enriching results", 1, 2), ("Enriching results", 2, 2)]


def test_run_enrichments_on_empty_input(only_registered: _RegistryInstaller) -> None:
    """No findings yields no results without touching the registry."""
    only_registered(_GoodPlugin)

    assert run_enrichments([]) == []
