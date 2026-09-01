"""Verify deterministic parser fuzzing accepts typed outcomes and leaves no temporary artifacts."""

from pathlib import Path

import pytest
from fuzz_target import fuzz_one_input
from helpers import DeterministicRandomSource, build_spec_vault
from test_reader import _base_fields
from test_writer import _XorBackend
from tools.run_passwordsafe_fuzz import main



#### Build one valid fabricated seed independently of the production reader and writer.
####
def _valid_seed() -> bytes:
    return build_spec_vault(
        _XorBackend(),
        b"fabricated-fuzz-passphrase",
        _base_fields(),
        salt=bytes(range(32)),
        iterations=3,
        content_key=bytes(range(32, 64)),
        hmac_key=bytes(range(64, 96)),
        iv=bytes(range(16)),
        random_source=DeterministicRandomSource(bytes(index % 251 for index in range(4096))),
    )



#### Accept malformed and authenticated inputs while removing every target-owned temporary artifact.
####
def test_fuzz_one_input_has_only_typed_outcomes_and_no_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "fuzz-workspace"
    workspace.mkdir()
    monkeypatch.setenv("BONOBO_FUZZ_WORKSPACE", str(workspace))

    fuzz_one_input(b"")
    fuzz_one_input(b"PWS3")
    fuzz_one_input(_valid_seed())

    assert tuple(workspace.iterdir()) == ()



#### Replay and mutate a hexadecimal corpus through the deadline-enforced command boundary.
####
def test_deterministic_fuzz_runner_completes_small_corpus(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "empty.hex").write_text("\n", encoding="ascii")
    (corpus / "valid.hex").write_text(_valid_seed().hex() + "\n", encoding="ascii")

    status = main(
        (
            "--corpus",
            str(corpus),
            "--iterations",
            "12",
            "--deadline-seconds",
            "2",
        )
    )

    assert status == 0
