"""Enrichment plugin contract, registry, and runner."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable

from pyrsistencesniper.core.models import AnnotatedResult, Enrichment, Finding

logger = logging.getLogger(__name__)

_ENRICHMENT_REGISTRY: list[type[EnrichmentPlugin]] = []


class EnrichmentPlugin(ABC):
    """Base for plugins that attach supplementary data to a finding."""

    provider: str = ""

    @abstractmethod
    def enrich(self, finding: Finding) -> Enrichment | None:
        """Return an Enrichment for the given finding, or None to skip it."""


def register_enrichment(cls: type[EnrichmentPlugin]) -> type[EnrichmentPlugin]:
    """Class decorator that adds an enrichment plugin to the global registry."""
    _ENRICHMENT_REGISTRY.append(cls)
    return cls


def _enrich_one(finding: Finding) -> tuple[Enrichment, ...]:
    """Run every registered enrichment against a finding, skipping failures."""
    enrichments: list[Enrichment] = []
    for plugin_cls in _ENRICHMENT_REGISTRY:
        try:
            enrichment = plugin_cls().enrich(finding)
        except Exception as exc:
            logger.warning("Enrichment %s failed: %s", plugin_cls.__name__, exc)
            logger.debug("Enrichment error details:", exc_info=True)
            continue
        if enrichment is not None:
            enrichments.append(enrichment)
    return tuple(enrichments)


def run_enrichments(
    findings: list[Finding],
    *,
    progress: Callable[[str, int, int], None] | None = None,
) -> list[AnnotatedResult]:
    """Attach the output of every registered enrichment to each finding."""
    total = len(findings)
    results: list[AnnotatedResult] = []
    for index, finding in enumerate(findings):
        if progress is not None:
            progress("Enriching results", index + 1, total)
        results.append((finding, _enrich_one(finding)))
    return results
