"""Define immutable non-secret edit metadata for application record commands.

Drafts carry only fields approved for application presentation.  Passwords and
URLs cross the facade separately in closable secret owners and never enter this
DTO, snapshots, diagnostics, or public representations.
"""

from dataclasses import dataclass

from .types import RecordKey



#### Retain one generation-bound non-secret record edit draft.
####
#### A `None` key represents a new record.  Existing-record revisions stay in
#### private facade maps so callers never receive PasswordSafe identities.
####
@dataclass(frozen=True, slots=True)
class RecordDraft:
    key: RecordKey | None
    generation: int
    title: str
    group: str
    username: str
    protected: bool



    #### Reject malformed UI metadata before it reaches session mutation code.
    ####
    def __post_init__(self) -> None:
        if self.key is not None and not isinstance(self.key, RecordKey):
            raise TypeError("record draft key is invalid")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 0:
            raise ValueError("record draft generation is invalid")
        if not all(isinstance(value, str) for value in (self.title, self.group, self.username)):
            raise TypeError("record draft public fields must be text")
        if not isinstance(self.protected, bool):
            raise TypeError("record draft protection marker is invalid")
