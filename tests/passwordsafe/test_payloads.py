"""Verify mutable inline owners and bounded deferred CBC field payloads.

All payloads are fabricated.  The deterministic identity block transform exists
only to make independently calculated CBC framing observable in these tests.
"""

import copy
import pickle
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol, cast

import pytest

from bonobo_core.passwordsafe.crypto import TwofishKey
from bonobo_core.passwordsafe.payloads import EncryptedSpan, EncryptedSpanPayload, InlinePayload, PayloadClosedError
from bonobo_core.passwordsafe.secrets import SecretBuffer



#### Provide an identity block transform so CBC expectations stay hand-checkable.
####
class _IdentityKey:



    #### Return the supplied block unchanged for the unused encryption direction.
    ####
    def encrypt_block(self, block: bytes) -> bytes:
        return block



    #### Return ciphertext unchanged before the CBC layer applies its prior block.
    ####
    def decrypt_block(self, block: bytes) -> bytes:
        return block



    #### Complete deterministic context cleanup without retaining native state.
    ####
    def close(self) -> None:
        return None



#### Yield identity keys while proving the content-key owner remains caller-owned.
####
class _IdentityBackend:



    #### Validate borrowed key availability and yield one fixed test transformer.
    ####
    @contextmanager
    def key(self, key_material: SecretBuffer) -> Iterator[TwofishKey]:
        key_material.borrow()
        yield _IdentityKey()



    #### Complete the protocol gate without introducing a production fallback.
    ####
    def self_test(self) -> None:
        return None



#### Describe the bounded snapshot surface consumed by deferred payloads.
####
class _SnapshotReader(Protocol):
    size: int



    #### Read one bounded exact ciphertext range.
    ####
    def read_at(self, offset: int, length: int) -> bytes:
        raise NotImplementedError



#### Retain fabricated ciphertext and record every bounded offset request.
####
class _RecordingSnapshot:
    calls: list[tuple[int, int]]



    #### Retain immutable fabricated ciphertext without a filesystem dependency.
    ####
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.size = len(data)
        self.calls = []
        self.read_bytes_calls = 0



    #### Return the requested exact span and record its bounded size.
    ####
    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        return self._data[offset:offset + length]



    #### Fail if deferred code attempts an unbounded convenience materialization.
    ####
    def read_bytes(self) -> bytes:
        self.read_bytes_calls += 1
        raise AssertionError("deferred payload used unbounded read_bytes")



#### Inject one partial or failed final inline wipe before allowing retry.
####
class _RetryWipeBuffer(bytearray):



    #### Retain one failure that triggers only on the first full zeroing slice.
    ####
    def __init__(self, data: bytes, failure: BaseException) -> None:
        super().__init__(data)
        self._failure: BaseException | None = failure



    #### Partially wipe, raise once, then permit the retry to finish zeroing.
    ####
    def __setitem__(self, key: int | slice, value: int | bytes) -> None:  # type: ignore[override]
        if isinstance(key, slice) and self._failure is not None:
            failure = self._failure
            self._failure = None
            super().__setitem__(slice(0, 3), b"\0\0\0")
            raise failure
        super().__setitem__(key, value)  # type: ignore[index, assignment]



#### Independently encrypt field plaintext under identity-block CBC.
####
def _cbc_ciphertext(plaintext: bytes, initial: bytes) -> bytes:
    previous = initial
    output = bytearray()
    for offset in range(0, len(plaintext), 16):
        block = plaintext[offset:offset + 16]
        encrypted = bytes(block[index] ^ previous[index] for index in range(16))
        output.extend(encrypted)
        previous = encrypted
    return bytes(output)



#### Construct one valid deferred field with a nonzero snapshot offset.
####
def _deferred_payload(
    data: bytes,
) -> tuple[EncryptedSpanPayload, _RecordingSnapshot, SecretBuffer, EncryptedSpan]:
    frame = len(data).to_bytes(4, "little") + b"\x29" + data
    frame += bytes((-len(frame)) % 16)
    previous = bytes(range(16))
    prefix = b"encrypted-prefix"
    ciphertext = _cbc_ciphertext(frame, previous)
    snapshot = _RecordingSnapshot(prefix + ciphertext + b"encrypted-suffix")
    key = SecretBuffer.from_bytes(bytes(32))
    span = EncryptedSpan(
        backend=_IdentityBackend(),
        content_key=key,
        previous_block=previous,
        ciphertext_offset=len(prefix),
        ciphertext_length=len(ciphertext),
        frame_offset=5,
        payload_length=len(data),
    )
    return EncryptedSpanPayload(cast(_SnapshotReader, snapshot), span), snapshot, key, span



#### Adopt inline mutable storage and wipe that exact object on close.
####
def test_inline_payload_owns_and_wipes_mutable_bytes() -> None:
    storage = bytearray(b"fabricated-secret")
    payload = InlinePayload.take_ownership(storage)

    assert payload.length == 17
    assert b"".join(bytes(chunk) for chunk in payload.iter_chunks(4)) == b"fabricated-secret"
    payload.close()
    payload.close()

    assert storage == bytearray(17)
    assert payload.closed
    with pytest.raises(PayloadClosedError, match="field payload is closed"):
        tuple(payload.iter_chunks(4))



#### Reject invalid chunk sizes before borrowing inline secret storage.
####
@pytest.mark.parametrize("chunk_size", [0, -1, 65_537, True, 1.5])
def test_inline_payload_rejects_bad_chunk_sizes(chunk_size: object) -> None:
    payload = InlinePayload.from_bytes(b"payload")

    with pytest.raises((TypeError, ValueError)):
        tuple(payload.iter_chunks(cast(int, chunk_size)))

    payload.close()



#### Stream declared payload bytes only, preserving partial caller chunk bounds.
####
@pytest.mark.parametrize("chunk_size", [1, 7, 16, 17, 31, 64])
def test_encrypted_span_streams_partial_chunks_without_read_bytes(chunk_size: int) -> None:
    expected = bytes(range(251)) * 3
    payload, snapshot, key, _span = _deferred_payload(expected)

    chunks = [bytes(chunk) for chunk in payload.iter_chunks(chunk_size)]

    assert b"".join(chunks) == expected
    assert all(0 < len(chunk) <= chunk_size for chunk in chunks)
    assert snapshot.read_bytes_calls == 0
    assert all(length <= 65_536 and length % 16 == 0 for _offset, length in snapshot.calls)
    assert not key.closed
    payload.close()
    key.close()



#### Refuse inconsistent CBC spans before reading ciphertext or borrowing keys.
####
@pytest.mark.parametrize(
    "changes",
    [
        {"ciphertext_offset": -1},
        {"ciphertext_length": 15},
        {"frame_offset": 4},
        {"payload_length": -1},
        {"payload_length": 0x1_0000_0000},
    ],
)
def test_encrypted_span_rejects_invalid_bounds(changes: dict[str, int]) -> None:
    key = SecretBuffer.from_bytes(bytes(32))
    values = {
        "ciphertext_offset": 0,
        "ciphertext_length": 16,
        "frame_offset": 5,
        "payload_length": 1,
    }
    values.update(changes)

    with pytest.raises(ValueError):
        EncryptedSpan(
            backend=_IdentityBackend(),
            content_key=key,
            previous_block=bytes(16),
            **values,
        )

    key.close()



#### Make deferred close terminal without closing borrowed key or snapshot owners.
####
def test_encrypted_span_close_is_idempotent_and_borrow_preserving() -> None:
    payload, snapshot, key, _span = _deferred_payload(b"fabricated")

    payload.close()
    payload.close()

    assert payload.closed
    assert not key.closed
    assert snapshot.calls == []
    with pytest.raises(PayloadClosedError, match="field payload is closed"):
        tuple(payload.iter_chunks(8))
    key.close()



#### Wipe a suspended yielded chunk and prevent any bytes after payload close.
####
@pytest.mark.parametrize("chunk_size", [1, 7, 16, 17, 64])
def test_encrypted_span_close_terminates_suspended_iterator(chunk_size: int) -> None:
    payload, _snapshot, key, _span = _deferred_payload(bytes(range(64)))
    iterator = payload.iter_chunks(chunk_size)
    yielded = next(iterator)

    payload.close()

    with pytest.raises(ValueError, match="released memoryview"):
        bytes(yielded)
    with pytest.raises(PayloadClosedError, match="field payload is closed"):
        next(iterator)
    key.close()



#### Fork only deferred CBC metadata while keeping borrowed owners caller-owned.
####
def test_encrypted_span_retain_has_independent_lifecycle() -> None:
    expected = bytes(range(64))
    payload, snapshot, key, _span = _deferred_payload(expected)
    retained = payload.retain()

    assert snapshot.calls == []
    payload.close()

    assert b"".join(bytes(chunk) for chunk in retained.iter_chunks(9)) == expected
    assert not key.closed
    retained.close()
    key.close()



#### Share inline storage until the final retained lease closes and wipes it.
####
def test_inline_payload_retain_wipes_only_after_last_lease() -> None:
    storage = bytearray(b"fabricated-secret")
    first = InlinePayload.take_ownership(storage)
    second = first.retain()

    first.close()

    assert storage == bytearray(b"fabricated-secret")
    assert b"".join(bytes(chunk) for chunk in second.iter_chunks(5)) == b"fabricated-secret"
    second.close()
    assert storage == bytearray(17)



#### Keep the final inline lease pending and unusable until a failed wipe retries.
####
@pytest.mark.parametrize("failure", [ValueError("wipe failed"), KeyboardInterrupt("wipe interrupted")])
def test_inline_payload_final_wipe_is_retryable_after_partial_failure(failure: BaseException) -> None:
    storage = _RetryWipeBuffer(b"fabricated-secret", failure)
    first = InlinePayload.take_ownership(storage)
    final = first.retain()
    first.close()

    with pytest.raises(type(failure)) as caught:
        final.close()

    assert caught.value is failure
    pending_after_failure = final.closed
    assert not pending_after_failure
    assert storage[:3] == b"\0\0\0"
    with pytest.raises(PayloadClosedError, match="field payload is closed"):
        tuple(final.iter_chunks(4))
    with pytest.raises(PayloadClosedError, match="field payload is closed"):
        final.retain()

    final.close()
    closed_after_retry = final.closed
    assert closed_after_retry
    assert storage == bytearray(17)



#### Finalization suppresses a partial wipe failure while retaining retry state.
####
def test_inline_payload_finalizer_retries_pending_wipe() -> None:
    storage = _RetryWipeBuffer(b"fabricated-secret", KeyboardInterrupt("wipe interrupted"))
    first = InlinePayload.take_ownership(storage)
    final = first.retain()
    first.close()

    final.__del__()
    pending_after_failure = final.closed
    assert not pending_after_failure

    final.__del__()
    closed_after_retry = final.closed
    assert closed_after_retry
    assert storage == bytearray(17)



#### Exhaust every suspended iterator before re-raising and retry only failures.
####
@pytest.mark.parametrize(
    ("first_failure", "last_failure"),
    [
        (ValueError("first iterator failure"), KeyboardInterrupt("last iterator failure")),
        (KeyboardInterrupt("first iterator interruption"), ValueError("last iterator failure")),
    ],
)
def test_encrypted_span_close_is_exhaustive_and_retryable(
    monkeypatch: pytest.MonkeyPatch,
    first_failure: BaseException,
    last_failure: BaseException,
) -> None:
    from bonobo_core.passwordsafe import payloads

    payload, _snapshot, key, _span = _deferred_payload(bytes(range(48)))
    iterators = [payload.iter_chunks(4) for _index in range(3)]
    yielded = [next(iterator) for iterator in iterators]
    original = payloads._EncryptedSpanIterator._close_from_owner
    attempts: list[payloads._EncryptedSpanIterator] = []



    #### Fail the first and last initial close calls while the middle cleans up.
    ####
    def fail_edges(iterator: payloads._EncryptedSpanIterator) -> None:
        attempts.append(iterator)
        if len(attempts) == 1:
            raise first_failure
        if len(attempts) == 3:
            raise last_failure
        original(iterator)

    monkeypatch.setattr(payloads._EncryptedSpanIterator, "_close_from_owner", fail_edges)

    with pytest.raises(type(first_failure)) as caught:
        payload.close()

    assert caught.value is first_failure
    first_attempt_count = len(attempts)
    assert first_attempt_count == 3
    pending_after_failure = payload.closed
    assert not pending_after_failure
    for iterator in iterators:
        with pytest.raises(PayloadClosedError, match="field payload is closed"):
            next(iterator)

    payload.close()

    closed_after_retry = payload.closed
    assert closed_after_retry
    final_attempt_count = len(attempts)
    assert final_attempt_count == 5
    for view in yielded:
        with pytest.raises(ValueError, match="released memoryview"):
            bytes(view)
    key.close()



#### Deferred finalization exhausts later iterators before suppressing one failure.
####
def test_encrypted_span_finalizer_is_exhaustive_and_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    from bonobo_core.passwordsafe import payloads

    payload, _snapshot, key, _span = _deferred_payload(bytes(range(32)))
    iterators = [payload.iter_chunks(4) for _index in range(2)]
    views = [next(iterator) for iterator in iterators]
    original = payloads._EncryptedSpanIterator._close_from_owner
    attempts = 0



    #### Fail the first close call once and clean every later/retried iterator.
    ####
    def fail_first(iterator: payloads._EncryptedSpanIterator) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt("iterator finalizer interruption")
        original(iterator)

    monkeypatch.setattr(payloads._EncryptedSpanIterator, "_close_from_owner", fail_first)

    payload.__del__()
    assert attempts == 2
    pending_after_failure = payload.closed
    assert not pending_after_failure

    payload.__del__()
    assert attempts == 3
    closed_after_retry = payload.closed
    assert closed_after_retry
    for view in views:
        with pytest.raises(ValueError, match="released memoryview"):
            bytes(view)
    key.close()



#### Exercise every generic copy and serialization path against one payload owner.
####
def _assert_payload_copy_and_pickle_rejected(payload: InlinePayload | EncryptedSpanPayload) -> None:
    with pytest.raises(TypeError, match="field payload cannot be copied or serialized"):
        copy.copy(payload)
    with pytest.raises(TypeError, match="field payload cannot be copied or serialized"):
        copy.deepcopy(payload)
    with pytest.raises(TypeError, match="field payload cannot be copied or serialized"):
        pickle.dumps(payload)

    payload.close()



#### Reject duplication and serialization of both secret-bearing payload owners.
####
def test_payloads_reject_copy_and_pickle() -> None:
    inline = InlinePayload.from_bytes(b"secret")
    deferred, _snapshot, key, _span = _deferred_payload(b"x")

    _assert_payload_copy_and_pickle_rejected(inline)
    _assert_payload_copy_and_pickle_rejected(deferred)

    key.close()



#### Reject generic duplication and serialization of secret-bearing span metadata.
####
def test_encrypted_span_rejects_copy_and_pickle() -> None:
    payload, _snapshot, key, span = _deferred_payload(b"x")

    with pytest.raises(TypeError, match="encrypted span cannot be copied or serialized"):
        copy.copy(span)
    with pytest.raises(TypeError, match="encrypted span cannot be copied or serialized"):
        copy.deepcopy(span)
    with pytest.raises(TypeError, match="encrypted span cannot be copied or serialized"):
        pickle.dumps(span)

    payload.close()
    key.close()
