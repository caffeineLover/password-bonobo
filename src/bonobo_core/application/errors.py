"""Map PasswordSafe failures to stable, presentation-safe application metadata.

The mapper intentionally reads only public exception types.  It does not retain
exception messages, paths, record identifiers, decrypted data, or native details.
"""

from dataclasses import dataclass
from enum import StrEnum

from bonobo_core.passwordsafe import (
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



#### Define the closed failure reasons application clients may localize and present.
####
class ApplicationFailureReason(StrEnum):
    AUTHENTICATION_FAILED = "authentication-failed"
    INTEGRITY_FAILED = "integrity-failed"
    MALFORMED_VAULT = "malformed-vault"
    UNSUPPORTED_FORMAT = "unsupported-format"
    INCOMPATIBLE_EXPORT = "incompatible-export"
    RESOURCE_LIMIT = "resource-limit"
    CRYPTO_BACKEND = "crypto-backend"
    PROTECTED_RECORD = "protected-record"
    STALE_REVISION = "stale-revision"
    UNSAVED_CHANGES = "unsaved-changes"
    EXTERNAL_MODIFICATION = "external-modification"
    STORAGE = "storage"
    RECOVERY_AVAILABLE = "recovery-available"
    UNEXPECTED = "unexpected"



#### Carry a localization key selected from a closed, non-secret failure reason.
####
@dataclass(frozen=True, slots=True)
class ApplicationFailure:
    reason: ApplicationFailureReason
    presentation_key: str



_PRESENTATION_KEYS: dict[ApplicationFailureReason, str] = {
    reason: f"application.failure.{reason.value}" for reason in ApplicationFailureReason
}



#### Convert any core or unexpected failure into presentation-safe application data.
####
#### The branch order is exhaustive for every public PasswordSafe leaf class.
#### A public base error and every non-PasswordSafe exception fail closed as
#### `UNEXPECTED` without copying their potentially sensitive text.
####
def to_application_failure(error: BaseException) -> ApplicationFailure:
    if isinstance(error, AuthenticationError):
        reason = ApplicationFailureReason.AUTHENTICATION_FAILED
    elif isinstance(error, IntegrityError):
        reason = ApplicationFailureReason.INTEGRITY_FAILED
    elif isinstance(error, MalformedVaultError):
        reason = ApplicationFailureReason.MALFORMED_VAULT
    elif isinstance(error, UnsupportedFormatError):
        reason = ApplicationFailureReason.UNSUPPORTED_FORMAT
    elif isinstance(error, IncompatibleExportError):
        reason = ApplicationFailureReason.INCOMPATIBLE_EXPORT
    elif isinstance(error, ResourceLimitError):
        reason = ApplicationFailureReason.RESOURCE_LIMIT
    elif isinstance(error, CryptoBackendError):
        reason = ApplicationFailureReason.CRYPTO_BACKEND
    elif isinstance(error, ProtectedRecordError):
        reason = ApplicationFailureReason.PROTECTED_RECORD
    elif isinstance(error, StaleRevisionError):
        reason = ApplicationFailureReason.STALE_REVISION
    elif isinstance(error, UnsavedChangesError):
        reason = ApplicationFailureReason.UNSAVED_CHANGES
    elif isinstance(error, ExternalModificationError):
        reason = ApplicationFailureReason.EXTERNAL_MODIFICATION
    elif isinstance(error, StorageError):
        reason = ApplicationFailureReason.STORAGE
    elif isinstance(error, RecoveryAvailableError):
        reason = ApplicationFailureReason.RECOVERY_AVAILABLE
    elif isinstance(error, PasswordSafeError):
        reason = ApplicationFailureReason.UNEXPECTED
    else:
        reason = ApplicationFailureReason.UNEXPECTED
    return ApplicationFailure(reason, _PRESENTATION_KEYS[reason])
