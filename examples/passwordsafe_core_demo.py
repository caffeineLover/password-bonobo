"""Create and reopen one fixed synthetic PasswordSafe vault through the public core."""

from __future__ import annotations

import argparse
import sys
import warnings
from collections.abc import Sequence
from getpass import GetPassWarning, getpass
from pathlib import Path
from uuid import UUID

from bonobo_core.passwordsafe import NewRecord, SecretBuffer, VaultService



DESTINATION_NAME = "synthetic-demo.psafe3"
SYNTHETIC_TITLE = "Fabricated Example Login"
SYNTHETIC_PASSWORD = b"fabricated-credential"



#### Create fresh private service directories without following or reusing existing paths.
####
def _prepare_private_directories(parent: Path) -> tuple[Path, Path]:
    directories = (parent / ".bonobo-working", parent / ".bonobo-recovery")
    if any(directory.exists() or directory.is_symlink() for directory in directories):
        raise FileExistsError("synthetic demo private directory already exists")
    created: list[Path] = []
    try:
        for directory in directories:
            directory.mkdir(mode=0o700, exist_ok=False)
            created.append(directory)
    except OSError:
        for directory in reversed(created):
            directory.rmdir()
        raise
    return directories



#### Prompt twice and transfer separate mutable passphrase owners to create and reopen.
####
def _prompt_passphrases() -> tuple[SecretBuffer, SecretBuffer]:
    first = _read_master_input("Fabricated master input: ")
    repeated = _read_master_input("Repeat fabricated master input: ")
    if first != repeated:
        raise ValueError("fabricated master inputs do not match")
    encoded = bytearray(first.encode("utf-8"))
    del first
    del repeated
    reopen_encoded = bytearray(encoded)
    return (
        SecretBuffer.take_ownership(encoded),
        SecretBuffer.take_ownership(reopen_encoded),
    )



#### Read a hidden terminal input or a non-echoed redirected test input.
####
def _read_master_input(prompt: str) -> str:
    if sys.stdin.isatty():
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", GetPassWarning)
                return getpass(prompt)
        except GetPassWarning as error:
            raise RuntimeError("hidden terminal input is unavailable") from error
    print(prompt, end="", file=sys.stderr, flush=True)
    value = sys.stdin.readline()
    if value == "":
        raise ValueError("fabricated master input is required")
    return value.rstrip("\r\n")



#### Run the fixed synthetic create, save, reopen, inspect, and lock workflow.
####
def run_demo(directory: Path, botan_library: Path) -> None:
    output_directory = directory.resolve()
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = output_directory / DESTINATION_NAME
    if destination.exists():
        raise FileExistsError("synthetic demo destination already exists")

    working_directory, recovery_directory = _prepare_private_directories(output_directory)
    service = VaultService.with_botan(
        botan_library.resolve(),
        working_directory,
        recovery_directory,
    )
    create_passphrase, reopen_passphrase = _prompt_passphrases()
    session = None
    reopened = None
    try:
        session = service.create(destination, create_passphrase, database_name="Synthetic demonstration")
        session.add(
            NewRecord(
                UUID("33333333-3333-4333-8333-333333333333"),
                SYNTHETIC_TITLE,
                SecretBuffer.from_bytes(SYNTHETIC_PASSWORD),
                username="fabricated-user",
                url="https://example.invalid",
            ),
            session.revision,
        )
        service.save(session)
        session.lock()
        session = None

        reopened = service.open(destination, reopen_passphrase)
        records = reopened.records()
        if len(records) != 1 or records[0].title != SYNTHETIC_TITLE:
            raise RuntimeError("synthetic vault verification failed")
        reopened.lock()
        reopened = None
    finally:
        if session is not None:
            session.discard_and_lock()
        if reopened is not None:
            reopened.discard_and_lock()
        create_passphrase.close()
        reopen_passphrase.close()



#### Parse only the approved paths and report a redacted completion result.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--botan-library", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        run_demo(arguments.directory, arguments.botan_library)
    except (OSError, RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print("created, saved, reopened, and locked synthetic vault")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
