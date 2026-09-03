"""Progress bar wiring for the scan pipeline stages."""

from __future__ import annotations

import sys
from collections.abc import Callable

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
)


def make_progress_bar() -> tuple[Progress, Callable[[str, int, int], None]]:
    """Create a Rich progress bar and a callback that drives it."""
    console = Console(stderr=True)
    progress_bar = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        disable=not sys.stderr.isatty(),
    )

    current_task_id: TaskID | None = None
    current_stage: str | None = None
    current_total: int = 0

    def on_progress(stage: str, current: int, total: int) -> None:
        """Advance the current task, completing the previous stage on a change."""
        nonlocal current_task_id, current_stage, current_total
        if stage != current_stage:
            if current_task_id is not None:
                progress_bar.update(current_task_id, completed=current_total)
            current_task_id = progress_bar.add_task(stage, total=total)
            current_stage = stage
        current_total = total
        if current_task_id is not None:
            progress_bar.update(current_task_id, completed=current)

    return progress_bar, on_progress
