"""Verify compatibility traceability and the clean-room expression boundary."""

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from tools.check_compatibility import (
    check_clean_room_source,
    check_interop_fixture_evidence,
    check_interop_transaction_evidence,
    check_local_evidence_corpus,
    check_repository_contract,
    check_traceability_sources,
)



FEATURE_HEADER = """| ID | Feature family | Disposition | Evidence | Owner | Platforms | Data-loss | Security | Tests |
|---|---|---|---|---|---|---|---|---|
"""



#### Write the exact four synthetic fixture pairs used by compatibility-gate tests.
####
def _write_interop_fixture_evidence(repository_root: Path) -> tuple[str, Mapping[str, str]]:
    fixture_root = repository_root / "tests" / "fixtures" / "synthetic" / "passwordsafe"
    fixture_root.mkdir(parents=True)
    expectations = {
        "bonobo-0311": ("Bonobo", "0x0311"),
        "passwordsafe-current": ("Password Safe 3.72.1", "0x0311"),
        "gorilla-6728e85": ("Gorilla 6728e85", "0x0300"),
        "official-unknown-0302": (
            "Independent PasswordSafe V3 fixture authority",
            "0x0302",
        ),
    }
    references: list[str] = []
    approved_hashes: dict[str, str] = {}
    for index, (stem, (authority, format_version)) in enumerate(expectations.items()):
        fixture = fixture_root / f"{stem}.psafe3"
        fixture.write_bytes(f"fabricated encrypted fixture {index}".encode())
        manifest = fixture_root / f"{stem}.manifest.json"
        encrypted_sha256 = hashlib.sha256(fixture.read_bytes()).hexdigest()
        approved_hashes[stem] = encrypted_sha256
        manifest.write_text(
            json.dumps(
                {
                    "schema": "password-bonobo-interoperability-manifest-v1",
                    "fixture": fixture.name,
                    "authority": authority,
                    "authority_version": "synthetic-version",
                    "creation_method": "independent-format-constructor",
                    "format_version": format_version,
                    "encrypted_sha256": encrypted_sha256,
                    "entries": [],
                    "field_count": 0,
                    "header_field_count": 0,
                    "passphrase_input": "stdin",
                    "platform": "synthetic platform",
                    "record_count": 0,
                    "tooling": ["synthetic tool"],
                }
            ),
            encoding="utf-8",
        )
        references.extend((manifest.relative_to(repository_root).as_posix(), encrypted_sha256))
    return "\n".join(references), approved_hashes



#### Copy the approved redacted transaction record into an isolated gate fixture.
####
def _write_interop_transaction_evidence(repository_root: Path) -> tuple[str, str]:
    relative_path = Path("tests/fixtures/synthetic/passwordsafe/interop-transactions.json")
    source = (Path.cwd() / relative_path).read_bytes()
    destination = repository_root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(source)
    digest = hashlib.sha256(source).hexdigest()
    return f"{relative_path.as_posix()}\n{digest}\n", digest



#### Reject an independently fabricated camelCase identifier while permitting explicit neutral terms.
####
def test_clean_room_audit_rejects_short_camelcase_identifiers() -> None:
    source = (
        "Use the visible backup controls on macOS and consult formatV3.txt. "
        "Do not expose fabricatedPolicyState."
    )

    violations = check_clean_room_source(Path("oracles.md"), source)

    assert tuple(violation.token for violation in violations) == ("fabricatedPolicyState",)



#### Reject a fabricated camelCase identifier whose lowercase prefix is one letter long.
####
def test_clean_room_audit_rejects_one_letter_prefix_camelcase_identifier() -> None:
    violations = check_clean_room_source(Path("oracles.md"), "Select qAccessMode in the synthetic harness.")

    assert tuple(violation.token for violation in violations) == ("qAccessMode",)



#### Preserve ordinary prose, acronyms, and the explicit neutral clean-room allowlist.
####
def test_clean_room_audit_accepts_prose_acronyms_and_neutral_terms() -> None:
    source = "A visible control uses URL and JSON labels on macOS and iOS; consult formatV3.txt and Git %aI."

    assert check_clean_room_source(Path("oracles.md"), source) == ()



#### Reject a runtime-supplied fabricated identifier in nested local SDD Markdown only.
####
def test_local_sdd_corpus_rejects_runtime_prohibited_identifier_digest(tmp_path: Path) -> None:
    fabricated_token = "fabricatedLocalLeak"
    digest = hashlib.sha256(fabricated_token.encode("utf-8")).hexdigest()
    report_path = tmp_path / ".superpowers" / "sdd" / "fabricated-task" / "report.md"
    report_path.parent.mkdir(parents=True)
    report_path.write_text(f"Observed {fabricated_token} in local evidence.\n", encoding="utf-8")
    (report_path.with_suffix(".txt")).write_text(fabricated_token, encoding="utf-8")
    (tmp_path / "outside.md").write_text(fabricated_token, encoding="utf-8")

    violations = check_local_evidence_corpus(
        tmp_path,
        forbidden_identifier_digests=frozenset({digest}),
    )

    assert tuple(
        (violation.path, violation.line, violation.message, violation.token)
        for violation in violations
    ) == (
        (
            Path(".superpowers/sdd/fabricated-task/report.md"),
            1,
            "prohibited upstream identifier is present in local SDD evidence",
            None,
        ),
    )



#### Treat an absent ignored SDD evidence directory as a clean local corpus.
####
def test_local_sdd_corpus_is_clean_clone_safe(tmp_path: Path) -> None:
    fabricated_digest = hashlib.sha256(b"absentFabricatedLeak").hexdigest()

    assert check_local_evidence_corpus(
        tmp_path,
        forbidden_identifier_digests=frozenset({fabricated_digest}),
    ) == ()



#### Reject destructive Gorilla loss evidence from a normal modernized feature.
####
def test_traceability_rejects_loss_behavior_in_modernized_feature() -> None:
    dossier = """### GOR-BEH-001 - Merge records

### GOR-BEH-063 - Lose a resolution
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Merge|Modernized|GOR-BEH-001, GOR-BEH-063|O3|ALL|Critical|Critical|GOR-TEST-001|\n"
    )
    oracles = """### GOR-TEST-001 - Merge records

- Authority: `Gorilla`.
- Required clients: Bonobo and Gorilla at the pinned revision.
"""

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "GOR-BEH-063 must appear only in an Excluded feature" in messages



#### Expand compact evidence ranges so every intermediate behavior is mapped.
####
def test_traceability_expands_compact_behavior_ranges() -> None:
    dossier = """### GOR-BEH-001 - First behavior

### GOR-BEH-002 - Second behavior

### GOR-BEH-003 - Third behavior
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Lifecycle|Modernized|GOR-BEH-001"
        + chr(0x2013)
        + "003|O3|ALL|Critical|Critical|GOR-TEST-001|\n"
    )
    oracles = """### GOR-TEST-001 - Exercise lifecycle

- Authority: `Gorilla`.
- Required clients: Bonobo and Gorilla at the pinned revision.
"""

    assert check_traceability_sources(dossier, matrix, oracles) == ()



#### Accept disjoint merge parity, excluded characterization, and Bonobo no-loss authority.
####
def test_traceability_accepts_split_no_loss_contract() -> None:
    dossier = """### GOR-BEH-001 - Merge records

### GOR-BEH-063 - Lose a resolution
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Merge|Modernized|GOR-BEH-001|O3|ALL|Critical|Critical|"
        "GOR-TEST-001, GOR-TEST-055|\n"
        "|GOR-FEAT-002|Gorilla resolution loss|Excluded|GOR-BEH-063|O3|ALL|Critical|Critical|GOR-TEST-054|\n"
    )
    oracles = """### GOR-TEST-001 - Merge records

- Authority: `Gorilla`.
- Required clients: Bonobo and Gorilla at the pinned revision.

### GOR-TEST-054 - Characterize Gorilla resolution loss

- Authority: `Gorilla`.
- Contract: `excluded-gorilla-only-characterization`.
- Required clients: Gorilla at the pinned revision only.

### GOR-TEST-055 - Persist Bonobo resolution transactionally

- Authority: `Bonobo`.
- Coverage: transactional-merge-resolution-no-loss.
- Required clients: Bonobo.
"""

    assert check_traceability_sources(dossier, matrix, oracles) == ()



#### Reject reuse of the Gorilla-only characterization oracle by Bonobo's normal merge feature.
####
def test_traceability_rejects_characterization_oracle_in_modernized_feature() -> None:
    dossier = """### GOR-BEH-063 - Lose a resolution
"""
    matrix = FEATURE_HEADER + (
        "|GOR-FEAT-001|Merge|Modernized|GOR-BEH-063|O3|ALL|Critical|Critical|"
        "GOR-TEST-054, GOR-TEST-055|\n"
        "|GOR-FEAT-002|Gorilla resolution loss|Excluded|GOR-BEH-063|O3|ALL|Critical|Critical|GOR-TEST-054|\n"
    )
    oracles = """### GOR-TEST-054 - Characterize Gorilla resolution loss

- Authority: `Gorilla`.
- Contract: `excluded-gorilla-only-characterization`.
- Required clients: Gorilla at the pinned revision only.

### GOR-TEST-055 - Persist Bonobo resolution transactionally

- Authority: `Bonobo`.
- Coverage: transactional-merge-resolution-no-loss.
- Required clients: Bonobo.
"""

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "GOR-TEST-054 must appear only in the Excluded loss-characterization feature" in messages



#### Reject a feature-looking row that omits one required schema column.
####
def test_traceability_rejects_feature_row_with_missing_column() -> None:
    dossier = "### GOR-BEH-001 - Fabricated behavior\n"
    matrix = FEATURE_HEADER + "|GOR-FEAT-001|Fabricated|Required|GOR-BEH-001|O3|ALL|Critical|GOR-TEST-001|\n"
    oracles = "### GOR-TEST-001 - Fabricated oracle\n"

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "feature row GOR-FEAT-001 has 8 cells; expected 9" in messages



#### Reject a feature-looking row that adds one unsupported schema column.
####
def test_traceability_rejects_feature_row_with_extra_column() -> None:
    dossier = "### GOR-BEH-001 - Fabricated behavior\n"
    matrix = (
        FEATURE_HEADER
        + "|GOR-FEAT-001|Fabricated|Required|GOR-BEH-001|O3|ALL|Critical|Critical|unexpected|GOR-TEST-001|\n"
    )
    oracles = "### GOR-TEST-001 - Fabricated oracle\n"

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "feature row GOR-FEAT-001 has 10 cells; expected 9" in messages



#### Reject a feature table whose authored header differs from the exact schema.
####
def test_traceability_rejects_malformed_feature_header() -> None:
    dossier = "### GOR-BEH-001 - Fabricated behavior\n"
    matrix = """| ID | Feature family | Disposition | Evidence | Owner | Platforms | Data-loss | Security | Cases |
|---|---|---|---|---|---|---|---|---|
|GOR-FEAT-001|Fabricated|Required|GOR-BEH-001|O3|ALL|Critical|Critical|GOR-TEST-001|
"""
    oracles = "### GOR-TEST-001 - Fabricated oracle\n"

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
    )

    assert "feature table header does not match the required schema" in messages



#### Reject a correctly sized authored feature row whose stable ID is not exactly three digits.
####
def test_traceability_rejects_malformed_feature_identifier() -> None:
    dossier = "### GOR-BEH-001 - Fabricated behavior\n"
    matrix = (
        FEATURE_HEADER
        + "A prose example may mention GOR-FEAT-9 without authoring a row.\n"
        + "| Note | GOR-FEAT-9 | prose | only | outside | the | ID | position | here |\n"
        + "|GOR-FEAT-99|Fabricated|Required|GOR-BEH-001|O3|ALL|Critical|Critical|GOR-TEST-001|\n"
    )
    oracles = "### GOR-TEST-001 - Fabricated oracle\n"

    messages = tuple(
        violation.message
        for violation in check_traceability_sources(dossier, matrix, oracles)
        if "malformed identifier" in violation.message
    )

    assert messages == (
        "feature row GOR-FEAT-99 has malformed identifier; expected GOR-FEAT-NNN",
    )



#### Accept exact encrypted hashes, authorities, levels, and oracle-document links.
####
def test_interop_fixture_evidence_accepts_complete_redacted_pairs(tmp_path: Path) -> None:
    oracles, approved_hashes = _write_interop_fixture_evidence(tmp_path)

    assert check_interop_fixture_evidence(
        tmp_path,
        oracles,
        approved_hashes=approved_hashes,
    ) == ()



#### Reject a stale encrypted digest and an evidence pair absent from the oracle document.
####
def test_interop_fixture_evidence_rejects_digest_and_traceability_drift(tmp_path: Path) -> None:
    oracles, approved_hashes = _write_interop_fixture_evidence(tmp_path)
    manifest = (
        tmp_path
        / "tests"
        / "fixtures"
        / "synthetic"
        / "passwordsafe"
        / "bonobo-0311.manifest.json"
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["encrypted_sha256"] = "0" * 64
    document["passphrase"] = "unexpected plaintext slot"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    oracles = oracles.replace(
        "tests/fixtures/synthetic/passwordsafe/gorilla-6728e85.manifest.json",
        "",
    )

    messages = tuple(
        violation.message
        for violation in check_interop_fixture_evidence(
            tmp_path,
            oracles,
            approved_hashes=approved_hashes,
        )
    )

    assert "interoperability manifest digest does not match fixture: bonobo-0311" in messages
    assert "interoperability manifest top-level schema is not closed: bonobo-0311" in messages
    assert "interoperability manifest is not linked from the oracle catalog: gorilla-6728e85" in messages



#### Reject coordinated fixture-and-manifest drift against the independently pinned digest.
####
def test_interop_fixture_evidence_rejects_coordinated_digest_drift(tmp_path: Path) -> None:
    oracles, approved_hashes = _write_interop_fixture_evidence(tmp_path)
    fixture_root = tmp_path / "tests" / "fixtures" / "synthetic" / "passwordsafe"
    fixture = fixture_root / "bonobo-0311.psafe3"
    manifest = fixture_root / "bonobo-0311.manifest.json"
    fixture.write_bytes(b"coordinated replacement")
    replacement_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["encrypted_sha256"] = replacement_hash
    manifest.write_text(json.dumps(document), encoding="utf-8")
    oracles = oracles.replace(approved_hashes["bonobo-0311"], replacement_hash)

    messages = tuple(
        violation.message
        for violation in check_interop_fixture_evidence(
            tmp_path,
            oracles,
            approved_hashes=approved_hashes,
        )
    )

    assert "interoperability fixture does not match approved digest: bonobo-0311" in messages



#### Accept only the approved transaction identity, schema, and client/source relationships.
####
def test_interop_transaction_evidence_accepts_approved_record(tmp_path: Path) -> None:
    oracles, approved_digest = _write_interop_transaction_evidence(tmp_path)

    assert check_interop_transaction_evidence(
        tmp_path,
        oracles,
        approved_digest=approved_digest,
    ) == ()



#### Reject coordinated transaction drift even when the modified JSON remains redacted and valid.
####
def test_interop_transaction_evidence_rejects_approved_digest_drift(tmp_path: Path) -> None:
    oracles, approved_digest = _write_interop_transaction_evidence(tmp_path)
    path = tmp_path / "tests/fixtures/synthetic/passwordsafe/interop-transactions.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["transactions"][0]["no_edit_sha256"] = "0" * 64
    path.write_text(json.dumps(document), encoding="utf-8")

    messages = tuple(
        violation.message
        for violation in check_interop_transaction_evidence(
            tmp_path,
            oracles,
            approved_digest=approved_digest,
        )
    )

    assert "interoperability transaction record does not match approved digest" in messages



#### Reject an unreviewed producer field even when a caller approves the rewritten file digest.
####
def test_interop_transaction_evidence_closes_external_artifact_schema(tmp_path: Path) -> None:
    oracles, _approved_digest = _write_interop_transaction_evidence(tmp_path)
    path = tmp_path / "tests/fixtures/synthetic/passwordsafe/interop-transactions.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["external_artifacts"]["unexpected"] = "unreviewed"
    path.write_text(json.dumps(document), encoding="utf-8")
    rewritten_digest = hashlib.sha256(path.read_bytes()).hexdigest()

    messages = tuple(
        violation.message
        for violation in check_interop_transaction_evidence(
            tmp_path,
            oracles,
            approved_digest=rewritten_digest,
        )
    )

    assert "interoperability transaction external-artifact schema is not closed" in messages



#### Check the tracked compatibility corpus through the release-gate entry point.
####
def test_repository_compatibility_documents_pass() -> None:
    assert check_repository_contract(Path.cwd()) == ()
