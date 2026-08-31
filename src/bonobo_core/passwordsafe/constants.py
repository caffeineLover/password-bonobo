"""Define immutable PasswordSafe V3 format constants and parser resource budgets.

This module owns protocol values shared by future codec and schema components.  It
does not parse data, select format behavior, or perform cryptographic work.
"""

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Final



FILE_TAG: Final[bytes] = b"PWS3"
EOF_MARKER: Final[bytes] = b"PWS3-EOFPWS3-EOF"
BLOCK_BYTES: Final[int] = 16
SALT_BYTES: Final[int] = 32
ITERATION_BYTES: Final[int] = 4
KEY_CHECK_BYTES: Final[int] = 32
WRAPPED_KEY_BLOCKS: Final[int] = 4
WRAPPED_KEY_BYTES: Final[int] = WRAPPED_KEY_BLOCKS * BLOCK_BYTES
IV_BYTES: Final[int] = BLOCK_BYTES
HMAC_BYTES: Final[int] = 32
FIELD_LENGTH_BYTES: Final[int] = 4
FIELD_TYPE_BYTES: Final[int] = 1
FIELD_HEADER_BYTES: Final[int] = FIELD_LENGTH_BYTES + FIELD_TYPE_BYTES
FIELD_FIRST_BLOCK_DATA_BYTES: Final[int] = BLOCK_BYTES - FIELD_HEADER_BYTES
MINIMUM_ITERATIONS: Final[int] = 262_144
MAX_ITERATIONS: Final[int] = 10_000_000
MAX_RECORDS: Final[int] = 1_000_000
MAX_FIELDS: Final[int] = 2_000_000
# One maximum uint32 payload frame plus one MiB for the envelope, required
# schema fields, and future-compatible bounded metadata.
MAX_ENCRYPTED_FILE_BYTES: Final[int] = (1 << 32) + 1_048_576
MAX_INLINE_PAYLOAD_BYTES: Final[int] = 1_048_576
MAX_DECODED_TEXT_BYTES: Final[int] = 16_777_216
MAX_IO_CHUNK_BYTES: Final[int] = 65_536



#### Represent one on-disk PasswordSafe V3 version without normalizing it.
####
#### Later document code retains this exact unsigned value so ordinary saves can
#### preserve a supported source version instead of silently upgrading it.
####
@dataclass(frozen=True, order=True, slots=True)
class FormatVersion:
    value: int



    #### Validate that direct construction cannot create an invalid field value.
    ####
    def __post_init__(self) -> None:
        if not 0 <= self.value <= 0xFFFF:
            raise ValueError("format version must fit uint16")



    #### Construct a version from the unsigned value stored in a header field.
    ####
    #### Callers decoding untrusted bytes use this boundary before any version
    #### compatibility decision occurs.
    ####
    @classmethod
    def from_uint16(cls, value: int) -> FormatVersion:
        if not 0 <= value <= 0xFFFF:
            raise ValueError("format version must fit uint16")
        return cls(value)



    #### Encode this version in the PasswordSafe header's little-endian order.
    ####
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(2, "little")



    #### Report whether this version is editable under the approved V3 policy.
    ####
    @property
    def supported(self) -> bool:
        return 0x0300 <= self.value <= 0x0311



CURRENT_FORMAT_VERSION: Final[FormatVersion] = FormatVersion.from_uint16(0x0311)



#### Bound work and retained plaintext independently of attacker-declared sizes.
####
#### Callers may supply stricter immutable instances.  These defaults preserve
#### structural security invariants and are not a switch for disabling limits.
####
@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_iterations: int = MAX_ITERATIONS
    max_records: int = MAX_RECORDS
    max_fields: int = MAX_FIELDS
    max_inline_payload_bytes: int = MAX_INLINE_PAYLOAD_BYTES
    max_decoded_text_bytes: int = MAX_DECODED_TEXT_BYTES
    io_chunk_bytes: int = MAX_IO_CHUNK_BYTES
    max_encrypted_file_bytes: int = MAX_ENCRYPTED_FILE_BYTES



    #### Reject budgets that would disable progress or weaken approved resource ceilings.
    ####
    #### Parser callers may supply lower limits, but none may replace a structural
    #### ceiling with zero, a negative number, or a value beyond the reviewed default.
    ####
    def __post_init__(self) -> None:
        limits: tuple[tuple[str, int, int], ...] = (
            ("max_iterations", self.max_iterations, MAX_ITERATIONS),
            ("max_records", self.max_records, MAX_RECORDS),
            ("max_fields", self.max_fields, MAX_FIELDS),
            ("max_inline_payload_bytes", self.max_inline_payload_bytes, MAX_INLINE_PAYLOAD_BYTES),
            ("max_decoded_text_bytes", self.max_decoded_text_bytes, MAX_DECODED_TEXT_BYTES),
            ("io_chunk_bytes", self.io_chunk_bytes, MAX_IO_CHUNK_BYTES),
            ("max_encrypted_file_bytes", self.max_encrypted_file_bytes, MAX_ENCRYPTED_FILE_BYTES),
        )
        for name, value, ceiling in limits:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= ceiling:
                raise ValueError(f"{name} must be a positive integer no greater than {ceiling}")



#### Identify a header field within the PasswordSafe V3 header namespace.
####
#### Header and record values intentionally have distinct enum types because a
#### shared numeric type cannot communicate a field's enclosing structure.
####
class HeaderFieldType(IntEnum):
    VERSION = 0x00
    UUID = 0x01
    PREFERENCES = 0x02
    TREE_DISPLAY_STATUS = 0x03
    LAST_SAVE_TIME = 0x04
    LAST_SAVE_BY = 0x05
    LAST_SAVE_WHAT = 0x06
    LAST_SAVE_USER = 0x07
    LAST_SAVE_HOST = 0x08
    DATABASE_NAME = 0x09
    DATABASE_DESCRIPTION = 0x0A
    DATABASE_FILTERS = 0x0B
    RESERVED_0C = 0x0C
    RESERVED_0D = 0x0D
    RESERVED_0E = 0x0E
    RECENTLY_USED_ENTRIES = 0x0F
    NAMED_PASSWORD_POLICIES = 0x10
    EMPTY_GROUPS = 0x11
    YUBICO = 0x12
    LAST_MASTER_PASSWORD_CHANGE = 0x13
    END = 0xFF



#### Identify a record field within the PasswordSafe V3 record namespace.
####
#### Values recognized as opaque remain named here so the schema can preserve
#### them without incorrectly offering their sensitive contents to callers.
####
class RecordFieldType(IntEnum):
    UUID = 0x01
    GROUP = 0x02
    TITLE = 0x03
    USERNAME = 0x04
    NOTES = 0x05
    PASSWORD = 0x06
    CREATION_TIME = 0x07
    PASSWORD_MODIFICATION_TIME = 0x08
    LAST_ACCESS_TIME = 0x09
    PASSWORD_EXPIRY_TIME = 0x0A
    RESERVED_0B = 0x0B
    LAST_MODIFICATION_TIME = 0x0C
    URL = 0x0D
    AUTOTYPE = 0x0E
    PASSWORD_HISTORY = 0x0F
    PASSWORD_POLICY = 0x10
    PASSWORD_EXPIRY_INTERVAL = 0x11
    RUN_COMMAND = 0x12
    DOUBLE_CLICK_ACTION = 0x13
    EMAIL = 0x14
    PROTECTED = 0x15
    OWN_SYMBOLS = 0x16
    SHIFT_DOUBLE_CLICK_ACTION = 0x17
    PASSWORD_POLICY_NAME = 0x18
    KEYBOARD_SHORTCUT = 0x19
    RESERVED_1A = 0x1A
    TWO_FACTOR_KEY = 0x1B
    CREDIT_CARD_NUMBER = 0x1C
    CREDIT_CARD_EXPIRATION = 0x1D
    CREDIT_CARD_VERIFICATION_VALUE = 0x1E
    CREDIT_CARD_PIN = 0x1F
    QR_CODE = 0x20
    TOTP_CONFIG = 0x21
    TOTP_LENGTH = 0x22
    TOTP_TIME_STEP = 0x23
    TOTP_START_TIME = 0x24
    ATTACHMENT_TITLE = 0x25
    ATTACHMENT_MEDIA_TYPE = 0x26
    ATTACHMENT_FILE_NAME = 0x27
    ATTACHMENT_MODIFICATION_TIME = 0x28
    ATTACHMENT_CONTENT = 0x29
    PASSKEY_CREDENTIAL_ID = 0x2A
    PASSKEY_RELYING_PARTY_ID = 0x2B
    PASSKEY_USER_HANDLE = 0x2C
    PASSKEY_ALGORITHM_ID = 0x2D
    PASSKEY_PRIVATE_KEY = 0x2E
    PASSKEY_SIGN_COUNT = 0x2F
    CUSTOM_TEXT_FIELD = 0x30
    UNKNOWN_TESTING = 0xDF
    END = 0xFF



#### Classify a known field's wire representation and editing boundary.
####
#### The later schema assigns one kind per known field while preserving unknown
#### codes separately; this enum does not itself validate any payload.
####
class FieldKind(StrEnum):
    UUID = "uuid"
    TEXT = "text"
    TIME = "time"
    UINT32 = "uint32"
    UINT16 = "uint16"
    UINT8 = "uint8"
    BINARY = "binary"
    OPAQUE = "opaque"
    EMPTY = "empty"
