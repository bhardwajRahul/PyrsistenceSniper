"""Enrichment plugins that attach supplementary context to findings."""

from __future__ import annotations

from pyrsistencesniper.enrichment import triage as _triage
from pyrsistencesniper.enrichment.base import (
    EnrichmentPlugin,
    register_enrichment,
    run_enrichments,
)

__all__ = [
    "EnrichmentPlugin",
    "register_enrichment",
    "run_enrichments",
]

# Imported for its registration side effect; add a new enrichment the same way.
_ = _triage
