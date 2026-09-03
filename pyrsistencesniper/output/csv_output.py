"""CSV renderer with spreadsheet formula injection sanitizing."""

from __future__ import annotations

import csv
from typing import IO, Any

from pyrsistencesniper.core.models import AnnotatedResult, CheckFailure, HiveRecord
from pyrsistencesniper.output.base import OutputBase, label_for, sanitize_cell


class CsvOutput(OutputBase):
    """Writes findings as CSV with formula-injection-safe cell values."""

    def _open_kwargs(self) -> dict[str, Any]:
        """Let the csv writer control line endings itself."""
        return {"newline": ""}

    def _write(
        self,
        results: list[AnnotatedResult],
        out: IO[str],
        *,
        inventory: tuple[HiveRecord, ...] = (),
        failures: tuple[CheckFailure, ...] = (),
    ) -> None:
        """Write the findings table only."""
        # Scan integrity rows are left out on purpose: this format exists to be
        # parsed, and interleaving them would break every consumer of it.
        del inventory, failures
        if not results:
            return

        rows, fieldnames = self._flatten_results(results)
        sanitized = [
            {field: sanitize_cell(value) for field, value in row.items()}
            for row in rows
        ]
        writer = csv.writer(out)
        writer.writerow([label_for(field) for field in fieldnames])
        for row in sanitized:
            writer.writerow([row.get(field, "") for field in fieldnames])
