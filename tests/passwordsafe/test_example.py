"""Verify the public PasswordSafe demonstration through a subprocess boundary."""

import importlib.util
import os
import subprocess
import sys
import warnings
from getpass import GetPassWarning
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest



REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEMO_PATH = REPOSITORY_ROOT / "examples" / "passwordsafe_core_demo.py"



#### Load the standalone demonstration without making examples an installed package.
####
def _load_demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("passwordsafe_core_demo", DEMO_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("demonstration module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



#### Supply the explicitly qualified Botan library used by the integration suite.
####
@pytest.fixture
def botan_library() -> Path:
    configured = os.environ.get("BONOBO_TEST_BOTAN_LIBRARY")
    if configured is None:
        if os.environ.get("CI"):
            pytest.fail("CI must configure the qualified Botan test library")
        pytest.skip("a qualified Botan test library was not configured")
    library = Path(configured).resolve()
    if not library.is_file():
        pytest.fail("the required Botan test library is unavailable")
    return library



#### Create, save, reopen, and lock only a fixed synthetic demonstration vault.
####
def test_demo_creates_and_reopens_only_synthetic_vault(
    tmp_path: Path,
    botan_library: Path,
) -> None:
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            str(REPOSITORY_ROOT / "examples" / "passwordsafe_core_demo.py"),
            "--directory",
            str(tmp_path),
            "--botan-library",
            str(botan_library),
        ],
        cwd=REPOSITORY_ROOT,
        input="fabricated-master-input-one\nfabricated-master-input-one\n",
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "created, saved, reopened, and locked synthetic vault" in result.stdout
    assert "fabricated-credential" not in result.stdout + result.stderr
    assert "fabricated-master-input-one" not in result.stdout + result.stderr
    assert (tmp_path / "synthetic-demo.psafe3").is_file()



#### Refuse a preexisting destination before prompting or changing its bytes.
####
def test_demo_never_replaces_a_preexisting_destination(
    tmp_path: Path,
    botan_library: Path,
) -> None:
    destination = tmp_path / "synthetic-demo.psafe3"
    destination.write_bytes(b"preexisting sentinel")

    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            str(REPOSITORY_ROOT / "examples" / "passwordsafe_core_demo.py"),
            "--directory",
            str(tmp_path),
            "--botan-library",
            str(botan_library),
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert destination.read_bytes() == b"preexisting sentinel"
    assert "synthetic demo destination already exists" in result.stderr



#### Fail closed instead of accepting getpass's echoed-input fallback.
####
def test_demo_rejects_unavailable_hidden_terminal_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    demo = _load_demo()



    #### Simulate getpass warning that terminal echo cannot be disabled.
    ####
    def warn_about_echo(_prompt: str) -> str:
        warnings.warn("echo unavailable", GetPassWarning, stacklevel=2)
        return "must-not-be-returned"

    monkeypatch.setattr(demo.sys, "stdin", Mock(isatty=lambda: True))
    monkeypatch.setattr(demo, "getpass", warn_about_echo)

    with pytest.raises(RuntimeError, match="hidden terminal input is unavailable"):
        demo._read_master_input("Fabricated master input: ")



#### Reject a preexisting private workspace without changing or reusing it.
####
def test_demo_never_reuses_a_preexisting_private_directory(
    tmp_path: Path,
    botan_library: Path,
) -> None:
    working = tmp_path / ".bonobo-working"
    working.mkdir()
    sentinel = working / "unrelated.txt"
    sentinel.write_bytes(b"preexisting private data")

    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            str(REPOSITORY_ROOT / "examples" / "passwordsafe_core_demo.py"),
            "--directory",
            str(tmp_path),
            "--botan-library",
            str(botan_library),
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert sentinel.read_bytes() == b"preexisting private data"
    assert "synthetic demo private directory already exists" in result.stderr
    assert not (tmp_path / "synthetic-demo.psafe3").exists()
