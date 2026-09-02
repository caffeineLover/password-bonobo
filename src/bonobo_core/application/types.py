"""Define immutable, non-secret application state for UI and client adapters.

These DTOs deliberately exclude paths, PasswordSafe identities, revisions, URLs,
and decrypted values.  The application facade owns their lifecycle and clients
may retain them only as inert presentation state.
"""

from dataclasses import dataclass, field
from enum import StrEnum

from .errors import ApplicationFailure



#### Identify one facade-owned record without exposing its PasswordSafe handle.
####
@dataclass(frozen=True, slots=True, order=True)
class RecordKey:
    value: int



#### Carry one single-use facade decision identity without exposing its entropy.
####
@dataclass(frozen=True, slots=True)
class DecisionToken:
    value: bytes = field(repr=False)



#### Describe the complete non-secret state machine visible to application clients.
####
class ApplicationPhase(StrEnum):
    EMPTY = "empty"
    BUSY = "busy"
    UNLOCKED_CLEAN = "unlocked-clean"
    UNLOCKED_DIRTY = "unlocked-dirty"
    LOCKED = "locked"
    AWAITING_DECISION = "awaiting-decision"



#### Present the only record fields permitted in a list or search projection.
####
@dataclass(frozen=True, slots=True)
class RecordSummary:
    key: RecordKey
    title: str
    group: str
    username: str
    protected: bool



#### Capture one complete UI-safe application state without domain escape hatches.
####
#### Record projections may be filtered by the active safe search query, but they
#### never gain a URL, secret, or PasswordSafe identity as a result.
####
@dataclass(frozen=True, slots=True)
class ApplicationSnapshot:
    generation: int
    phase: ApplicationPhase
    display_label: str
    dirty: bool
    records: tuple[RecordSummary, ...]
    selected: RecordKey | None
    failure: ApplicationFailure | None
    decision: DecisionToken | None
