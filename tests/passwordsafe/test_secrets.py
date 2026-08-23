"""Verify owned secret buffers and leases close deterministically without disclosure.

CPython cannot guarantee physical zeroization of every temporary immutable
object, so these owners minimize copies and wipe their mutable storage.
"""

from collections.abc import Callable
from typing import cast

import pytest

from bonobo_core.passwordsafe.secrets import SecretBuffer, SecretClosedError, SecretLease



#### Wipe the caller's exact mutable storage after ownership is transferred.
####
#### Ownership deliberately retains the original bytearray so closing the owner
#### clears the sole mutable secret storage rather than a hidden copy.
####
def test_secret_buffer_wipes_owned_storage() -> None:
    storage = bytearray(b"fabricated-secret")
    secret = SecretBuffer.take_ownership(storage)

    secret.close()

    assert storage == bytearray(len(storage))
    assert secret.closed
    assert "fabricated-secret" not in repr(secret)



#### Make exactly one mutable copy when callers begin with immutable bytes.
####
def test_secret_buffer_from_bytes_borrows_read_only_data() -> None:
    secret = SecretBuffer.from_bytes(b"fabricated-secret")

    borrowed = secret.borrow()

    assert borrowed.readonly
    assert bytes(borrowed) == b"fabricated-secret"
    secret.close()
    assert bytes(borrowed) == b"\x00" * len(borrowed)



#### Refuse access after deterministic close without revealing the prior bytes.
####
def test_secret_buffer_rejects_borrow_after_close() -> None:
    secret = SecretBuffer.from_bytes(b"fabricated-secret")
    secret.close()

    with pytest.raises(SecretClosedError, match="secret buffer is closed") as caught:
        secret.borrow()

    assert "fabricated-secret" not in str(caught.value)
    assert "fabricated-secret" not in repr(caught.value)



#### Close a secret buffer when its context exits through an exception path.
####
def test_secret_buffer_context_closes_on_exception() -> None:
    storage = bytearray(b"fabricated-secret")

    with pytest.raises(RuntimeError, match="synthetic failure"), SecretBuffer.take_ownership(storage):
        raise RuntimeError("synthetic failure")

    assert storage == bytearray(len(storage))



#### Lease a separate bounded copy and wipe it when the lease ends.
####
def test_secret_lease_has_independent_bounded_lifetime() -> None:
    source = SecretBuffer.from_bytes(b"fabricated-secret")
    lease = SecretLease.copy_of(source, max_bytes=64)

    with lease as active_lease:
        assert bytes(active_lease.borrow()) == b"fabricated-secret"
        assert "fabricated-secret" not in repr(active_lease)
        assert isinstance(hash(active_lease), int)

    assert lease.closed
    assert bytes(source.borrow()) == b"fabricated-secret"
    with pytest.raises(SecretClosedError, match="secret buffer is closed"):
        lease.borrow()
    source.close()



#### Reject lease material that exceeds the caller-provided access bound.
####
def test_secret_lease_enforces_its_explicit_bound() -> None:
    with pytest.raises(ValueError, match="secret lease exceeds its byte limit"):
        SecretLease.from_bytes(b"fabricated-secret", max_bytes=1)



#### Keep source storage intact when a separately owned lease closes.
####
#### This uses an adopted bytearray rather than only a borrowed value so the test
#### proves a lease close cannot wipe the source owner's exact mutable storage.
####
def test_secret_lease_close_does_not_wipe_source_storage() -> None:
    source_storage = bytearray(b"fabricated-secret")
    source = SecretBuffer.take_ownership(source_storage)
    lease = SecretLease.copy_of(source, max_bytes=64)

    lease.close()

    assert source_storage == bytearray(b"fabricated-secret")
    assert bytes(source.borrow()) == b"fabricated-secret"
    source.close()



#### Disallow direct construction so callers cannot adopt shared or unbounded storage.
####
def test_secret_lease_constructor_cannot_bypass_copy_or_bound() -> None:
    shared_storage = bytearray(b"fabricated-secret")
    unsafe_constructor = cast(Callable[..., SecretLease], SecretLease)

    with pytest.raises(TypeError):
        unsafe_constructor(shared_storage)

    assert shared_storage == bytearray(b"fabricated-secret")



#### Reject zero, negative, and noninteger lease maxima before copying secret data.
####
def test_secret_lease_requires_a_finite_positive_maximum() -> None:
    for maximum in (0, -1, 1.5, 1_048_577):
        with pytest.raises(ValueError, match="secret lease byte limit"):
            SecretLease.from_bytes(b"fabricated-secret", max_bytes=maximum)  # type: ignore[arg-type]
