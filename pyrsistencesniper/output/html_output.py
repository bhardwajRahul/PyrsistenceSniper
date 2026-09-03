"""Interactive standalone HTML report renderer."""

from __future__ import annotations

from importlib.resources import files
from typing import IO, Any

from jinja2 import Environment

from pyrsistencesniper.core.models import AnnotatedResult, CheckFailure, HiveRecord
from pyrsistencesniper.output.base import OutputBase, label_for

_HTML_TEMPLATE = (
    files("pyrsistencesniper.output").joinpath("report.html.j2").read_text("utf-8")
)

_LAST_CHANGE_HELP = (
    "Approximate, in UTC. Set only from evidence whose timestamp is carried "
    "inside the artifact and survives collection: $MFT records and event log "
    "records. Filesystem modified times are never used (a collection may carry "
    "copy times) and registry key write times are never used (they date the "
    "key, not the value). An empty cell does not mean nothing changed; the "
    "Change Evidence column says which kind of empty it is."
)

_CHANGE_EVIDENCE_HELP = (
    "Why the Last Change cell holds what it holds. RESOLVED: dated. "
    "NOT_APPLICABLE: nothing can date this kind of finding, so no artifact "
    "would help. NO_ARTIFACT: evidence was declared but the $MFT or event log "
    "it needs was not collected or was cleared, so collecting it would help. "
    "NO_MATCH: the artifact was read and had nothing to say about this entry. "
    "REJECTED: times were found and every one was implausible. "
    "NOT_RUN: the timeline stage did not run."
)


def _dirty_hive_names(inventory: tuple[HiveRecord, ...]) -> list[str]:
    """Name the hives that were read but held uncommitted transactions."""
    return [
        f"{record.name} [{record.owner}]" if record.owner else record.name
        for record in inventory
        if record.dirty
    ]


def _count_severities(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings per severity level for the stats bar."""
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for row in rows:
        severity = row.get("severity", "")
        if severity in counts:
            counts[severity] += 1
    return counts


class HtmlOutput(OutputBase):
    """Renders findings into a dark-mode interactive HTML report."""

    def _write(
        self,
        results: list[AnnotatedResult],
        out: IO[str],
        *,
        inventory: tuple[HiveRecord, ...] = (),
        failures: tuple[CheckFailure, ...] = (),
    ) -> None:
        environment = Environment(autoescape=True)
        environment.policies["json.dumps_kwargs"] = {"default": str}
        template = environment.from_string(_HTML_TEMPLATE)
        rows, fieldnames = self._flatten_results(results)
        for (finding, _enrichments), row in zip(results, rows, strict=True):
            row["_change_candidates"] = list(finding.change_candidates)
        labels = {field: label_for(field) for field in fieldnames}
        out.write(
            template.render(
                results=rows,
                fieldnames=fieldnames,
                labels=labels,
                total=len(rows),
                severity_counts=_count_severities(rows),
                column_help={
                    "last_change": _LAST_CHANGE_HELP,
                    "change_evidence": _CHANGE_EVIDENCE_HELP,
                },
                unreadable_hives=self.unreadable_hives(inventory),
                dirty_hives=_dirty_hive_names(inventory),
                failed_checks=failures,
            )
        )
