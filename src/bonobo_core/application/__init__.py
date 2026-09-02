"""Expose the UI-independent Password Bonobo application contract.

This public package offers only immutable non-secret state, safe failure data,
and deterministic projections for adapters such as desktop and future mobile UI.
"""

from .errors import ApplicationFailure, ApplicationFailureReason
from .facade import ApplicationCommandError, CloseChoice, VaultApplication
from .ports import BrowserPort, ClipboardPort
from .projection import project_records, search_records
from .records import RecordDraft
from .types import ApplicationPhase, ApplicationSnapshot, DecisionToken, RecordKey, RecordSummary



__all__ = (
    "ApplicationCommandError",
    "ApplicationFailure",
    "ApplicationFailureReason",
    "ApplicationPhase",
    "ApplicationSnapshot",
    "BrowserPort",
    "ClipboardPort",
    "CloseChoice",
    "DecisionToken",
    "RecordDraft",
    "RecordKey",
    "RecordSummary",
    "VaultApplication",
    "project_records",
    "search_records",
)
