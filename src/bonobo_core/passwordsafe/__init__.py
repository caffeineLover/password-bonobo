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
    AuthenticationReason,
    CryptoBackendError,
    CryptoBackendReason,
    ExternalModificationError,
    FailureReason,
    FailureStage,
    IncompatibleExportError,
    IncompatibleExportReason,
    IntegrityError,
    IntegrityReason,
    MalformedReason,
    MalformedVaultError,
    OperationReason,
    PasswordSafeError,
    ProtectedRecordError,
    RecoveryAvailableError,
    ResourceLimitError,
    ResourceLimitReason,
    StaleRevisionError,
    StorageError,
    StorageReason,
    UnsavedChangesError,
    UnsupportedFormatError,
    UnsupportedFormatReason,
)
from .secrets import SecretBuffer, SecretClosedError, SecretLease



__all__ = (
    "CURRENT_FORMAT_VERSION",
    "MINIMUM_ITERATIONS",
    "AuthenticationError",
    "AuthenticationReason",
    "CryptoBackendError",
    "CryptoBackendReason",
    "ExternalModificationError",
    "FailureReason",
    "FailureStage",
    "FieldKind",
    "FormatVersion",
    "HeaderFieldType",
    "IncompatibleExportError",
    "IncompatibleExportReason",
    "IntegrityError",
    "IntegrityReason",
    "MalformedReason",
    "MalformedVaultError",
    "OperationReason",
    "PasswordSafeError",
    "ProtectedRecordError",
    "RecordFieldType",
    "RecoveryAvailableError",
    "ResourceLimitError",
    "ResourceLimitReason",
    "ResourceLimits",
    "SecretBuffer",
    "SecretClosedError",
    "SecretLease",
    "StaleRevisionError",
    "StorageError",
    "StorageReason",
    "UnsavedChangesError",
    "UnsupportedFormatError",
    "UnsupportedFormatReason",
)
