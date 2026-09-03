"""Timeline evidence resolution that approximates when each finding last changed."""

from __future__ import annotations

from pyrsistencesniper.timeline.base import Precision, TimeCandidate
from pyrsistencesniper.timeline.executor import TimelineExecutor

__all__ = ["Precision", "TimeCandidate", "TimelineExecutor"]
