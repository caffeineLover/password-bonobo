"""Expose the reviewed PasswordSafe domain primitives used by later core layers.

The package surface intentionally contains only constants, safe failures, and secret
owners at this stage; codecs, sessions, and storage remain separate responsibilities.
"""

from .constants import (
    CURRENT_FORMAT_VERSION,
    MINIMUM_ITERATIONS,
    FieldKind,
    FormatVersion,
    HeaderFieldType,
    RecordFieldType,
    ResourceLimits,
)
from .errors import (
    AuthenticationError,
    CryptoBackendError,
    ExternalModificationError,
    IncompatibleExportError,
    IntegrityError,
    MalformedVaultError,
    PasswordSafeError,
    ProtectedRecordError,
    RecoveryAvailableError,
    ResourceLimitError,
    StaleRevisionError,
    StorageError,
    UnsavedChangesError,
    UnsupportedFormatError,
)
from .secrets import SecretBuffer, SecretClosedError, SecretLease



__all__ = (
    "CURRENT_FORMAT_VERSION",
    "MINIMUM_ITERATIONS",
    "AuthenticationError",
    "CryptoBackendError",
    "ExternalModificationError",
    "FieldKind",
    "FormatVersion",
    "HeaderFieldType",
    "IncompatibleExportError",
    "IntegrityError",
    "MalformedVaultError",
    "PasswordSafeError",
    "ProtectedRecordError",
    "RecordFieldType",
    "RecoveryAvailableError",
    "ResourceLimitError",
    "ResourceLimits",
    "SecretBuffer",
    "SecretClosedError",
    "SecretLease",
    "StaleRevisionError",
    "StorageError",
    "UnsavedChangesError",
    "UnsupportedFormatError",
)
