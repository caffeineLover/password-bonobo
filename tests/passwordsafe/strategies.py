"""Generate bounded synthetic PasswordSafe documents and adversarial declarations for property evidence."""

from dataclasses import dataclass

from hypothesis import strategies as st

from bonobo_core.passwordsafe.constants import FormatVersion, HeaderFieldType, RecordFieldType



_FABRICATED_UUID = bytes.fromhex("22222222222242228222222222222222")
_SAFE_TEXT = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=12)
_BOUNDED_BINARY = st.binary(min_size=0, max_size=96)



#### Describe one valid generated vault plus one independently selected title mutation.
####
@dataclass(frozen=True, slots=True)
class LosslessVaultCase:
    version: FormatVersion
    fields: tuple[tuple[int, bytes], ...]
    target_record_ordinal: int
    target_field_type: RecordFieldType
    target_field_ordinal: int
    replacement_title: str



#### Encode one official custom text field from generated safe UTF-8 values.
####
def _custom_field(name: str, value: str, *, sensitive: bool) -> bytes:
    name_bytes = name.encode("utf-8")
    value_bytes = value.encode("utf-8")
    encoded = b"".join(
        (
            b"01",
            f"{len(name_bytes):04x}".encode("ascii"),
            name_bytes,
            b"02",
            f"{len(value_bytes):04x}".encode("ascii"),
            value_bytes,
            b"03",
            b"0001",
            b"1" if sensitive else b"0",
        )
    )
    return encoded



#### Draw one valid record with unusual ordering, optional duplicates, and bounded opaque content.
####
def _record_fields(
    draw: st.DrawFn,
    version: FormatVersion,
    record_ordinal: int,
) -> tuple[tuple[tuple[int, bytes], ...], int]:
    title_token = draw(_SAFE_TEXT)
    title = f"Title {record_ordinal} {title_token}".encode()
    password = f"fabricated-password-{record_ordinal}-{title_token}".encode()
    url_label = draw(_SAFE_TEXT)
    url = f"https://{url_label}.example.invalid/path".encode("ascii")
    fields: list[tuple[int, bytes]] = [
        (RecordFieldType.UUID, _FABRICATED_UUID),
        (RecordFieldType.TITLE, title),
        (RecordFieldType.PASSWORD, password),
        (RecordFieldType.URL, url),
        (draw(st.integers(min_value=0xE0, max_value=0xEF)), draw(_BOUNDED_BINARY)),
    ]
    if draw(st.booleans()):
        fields.append((RecordFieldType.URL, url + b"/duplicate"))
    if draw(st.booleans()):
        username = f"fabricated-user-{draw(_SAFE_TEXT)}".encode()
        fields.append((RecordFieldType.USERNAME, username))
    if version.value >= 0x030F and draw(st.booleans()):
        fields.extend(
            (
                (RecordFieldType.ATTACHMENT_MEDIA_TYPE, b"application/octet-stream"),
                (RecordFieldType.ATTACHMENT_CONTENT, draw(_BOUNDED_BINARY)),
            )
        )
    if version.value >= 0x0311 and draw(st.booleans()):
        fields.append(
            (
                RecordFieldType.CUSTOM_TEXT_FIELD,
                _custom_field(
                    f"Name {draw(_SAFE_TEXT)}",
                    f"Value {draw(_SAFE_TEXT)}",
                    sensitive=draw(st.booleans()),
                ),
            )
        )
    ordered = draw(st.permutations(fields))
    title_ordinal = next(
        ordinal
        for ordinal, (type_code, _payload) in enumerate(ordered)
        if type_code == RecordFieldType.TITLE
    )
    return (*ordered, (RecordFieldType.END, b"")), title_ordinal



#### Generate supported ordered vaults with unknowns, duplicates, custom properties, and targeted edits.
####
@st.composite
def lossless_vault_cases(draw: st.DrawFn) -> LosslessVaultCase:
    version = FormatVersion.from_uint16(draw(st.integers(min_value=0x0300, max_value=0x0311)))
    header_fields: list[tuple[int, bytes]] = [
        (HeaderFieldType.VERSION, version.to_bytes()),
        (draw(st.integers(min_value=0xE0, max_value=0xEF)), draw(_BOUNDED_BINARY)),
    ]
    if draw(st.booleans()):
        preferences = f"fabricated preference {draw(_SAFE_TEXT)}".encode()
        header_fields.append((HeaderFieldType.PREFERENCES, preferences))
        if draw(st.booleans()):
            header_fields.append((HeaderFieldType.PREFERENCES, preferences + b" duplicate"))
    if version.value >= 0x0302 and draw(st.booleans()):
        header_fields.append(
            (HeaderFieldType.DATABASE_NAME, f"Generated {draw(_SAFE_TEXT)}".encode())
        )
    fields: list[tuple[int, bytes]] = [*header_fields, (HeaderFieldType.END, b"")]
    record_count = draw(st.integers(min_value=1, max_value=2))
    title_ordinals: list[int] = []
    for record_ordinal in range(record_count):
        record_fields, title_ordinal = _record_fields(draw, version, record_ordinal)
        fields.extend(record_fields)
        title_ordinals.append(title_ordinal)
    target_record_ordinal = draw(st.integers(min_value=0, max_value=record_count - 1))
    replacement_title = f"Revised {draw(_SAFE_TEXT)}"
    return LosslessVaultCase(
        version,
        tuple(fields),
        target_record_ordinal,
        RecordFieldType.TITLE,
        title_ordinals[target_record_ordinal],
        replacement_title,
    )



#### Generate large uint32 declarations that cannot fit inside the bounded fabricated encrypted input.
####
def oversized_uint32_field_lengths() -> st.SearchStrategy[int]:
    boundaries = st.sampled_from((0x1000_0000, 0x7FFF_FFFF, 0xFFFF_FFFE, 0xFFFF_FFFF))
    return st.one_of(boundaries, st.integers(min_value=0x1000_0000, max_value=0xFFFF_FFFF))



#### Create one deterministic multi-mebibyte opaque attachment containing a caller-selected synthetic fragment.
####
def large_opaque_attachment(fragment: bytes) -> bytes:
    if not isinstance(fragment, bytes) or not fragment:
        raise ValueError("large attachment fragment must be nonempty bytes")
    target_length = 1024 * 1024 + 65_537
    repetitions = (target_length + len(fragment) - 1) // len(fragment)
    return (fragment * repetitions)[:target_length]
