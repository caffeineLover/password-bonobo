"""Expose the UI-independent Password Bonobo application contract.

This public package offers only immutable non-secret state, safe failure data,
and deterministic projections for adapters such as desktop and future mobile UI.
"""

from .errors import ApplicationFailure, ApplicationFailureReason
from .projection import project_records, search_records
from .types import ApplicationPhase, ApplicationSnapshot, DecisionToken, RecordKey, RecordSummary



__all__ = (
    "ApplicationFailure",
    "ApplicationFailureReason",
    "ApplicationPhase",
    "ApplicationSnapshot",
    "DecisionToken",
    "RecordKey",
    "RecordSummary",
    "project_records",
    "search_records",
)
