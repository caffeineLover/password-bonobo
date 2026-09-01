"""Replay and deterministically mutate the committed PasswordSafe parser fuzz corpus.

Each input executes in one persistent worker process so the parent can enforce a
cross-platform deadline and terminate a hung parser.  The target owns a private
temporary child per input, while the runner verifies that every child disappears.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import tempfile
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from pathlib import Path
from typing import Protocol, cast



_WORKSPACE_ENVIRONMENT = "BONOBO_FUZZ_WORKSPACE"
_TARGET_PATH = Path(__file__).resolve().parents[1] / "tests" / "passwordsafe" / "fuzz_target.py"



#### Describe the one dependency-free callable loaded from the isolated test target.
####
class _FuzzTarget(Protocol):



    #### Consume one arbitrary encrypted byte string or raise an observable failure.
    ####
    def __call__(self, data: bytes) -> None: ...



_LOADED_TARGET: _FuzzTarget | None = None



#### Load the repository fuzz target once per worker without making tests an import package.
####
def _load_target() -> _FuzzTarget:
    global _LOADED_TARGET
    if _LOADED_TARGET is not None:
        return _LOADED_TARGET
    specification = importlib.util.spec_from_file_location("password_bonobo_fuzz_target", _TARGET_PATH)
    if specification is None or specification.loader is None:
        raise RuntimeError("fuzz target cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    candidate: object = getattr(module, "fuzz_one_input", None)
    if not callable(candidate):
        raise RuntimeError("fuzz target callable is unavailable")
    _LOADED_TARGET = cast(_FuzzTarget, candidate)
    return _LOADED_TARGET



#### Execute one input inside the deadline-enforced worker process.
####
def _execute_input(data: bytes) -> None:
    _load_target()(data)



#### Decode every stable hexadecimal seed in lexical path order.
####
def _load_corpus(corpus_directory: Path) -> tuple[bytes, ...]:
    if not corpus_directory.is_dir():
        raise ValueError("fuzz corpus directory is unavailable")
    seeds: list[bytes] = []
    for path in sorted(corpus_directory.rglob("*.hex")):
        lines = (
            line.strip()
            for line in path.read_text(encoding="ascii").splitlines()
            if not line.lstrip().startswith("#")
        )
        try:
            seeds.append(bytes.fromhex("".join(lines)))
        except ValueError:
            raise ValueError("fuzz corpus contains invalid hexadecimal data") from None
    if not seeds:
        raise ValueError("fuzz corpus contains no hexadecimal seeds")
    return tuple(seeds)



#### Return one deterministic bit flip, truncation, insertion, or uint32-length mutation.
####
def _mutate(seed: bytes, mutation_index: int) -> bytes:
    mode = mutation_index % 4
    if mode == 0:
        if not seed:
            return b"\x01"
        position = (mutation_index * 17) % len(seed)
        changed = bytearray(seed)
        changed[position] ^= 1 << (mutation_index % 8)
        return bytes(changed)
    if mode == 1:
        if not seed:
            return seed
        return seed[: (mutation_index * 13) % len(seed)]
    if mode == 2:
        position = 0 if not seed else (mutation_index * 19) % (len(seed) + 1)
        inserted = bytes(((mutation_index * 29) & 0xFF,))
        return seed[:position] + inserted + seed[position:]
    changed = bytearray(seed)
    if len(changed) < 156:
        changed.extend(bytes(156 - len(changed)))
    changed[152:156] = (0xFFFF_FFFF - (mutation_index % 256)).to_bytes(4, "little")
    return bytes(changed)



#### Yield exact corpus replay first, then deterministic mutations for the requested budget.
####
def _inputs(corpus: tuple[bytes, ...], iterations: int) -> tuple[bytes, ...]:
    generated: list[bytes] = []
    for index in range(iterations):
        seed = corpus[index % len(corpus)]
        generated.append(seed if index < len(corpus) else _mutate(seed, index - len(corpus)))
    return tuple(generated)



#### Run every input with a killable deadline and reject target-owned artifact leaks.
####
def _run(corpus: tuple[bytes, ...], iterations: int, deadline_seconds: float) -> None:
    previous_workspace = os.environ.get(_WORKSPACE_ENVIRONMENT)
    with tempfile.TemporaryDirectory(prefix="password-bonobo-fuzz-run-") as temporary_name:
        workspace = Path(temporary_name)
        os.environ[_WORKSPACE_ENVIRONMENT] = str(workspace)
        executor = ProcessPoolExecutor(max_workers=1)
        try:
            for index, data in enumerate(_inputs(corpus, iterations)):
                future = executor.submit(_execute_input, data)
                try:
                    future.result(timeout=deadline_seconds)
                except FutureTimeoutError:
                    executor.terminate_workers()
                    raise RuntimeError(f"fuzz input {index} exceeded its deadline") from None
                except Exception as error:
                    executor.terminate_workers()
                    raise RuntimeError(
                        f"fuzz input {index} raised untyped {type(error).__name__}"
                    ) from None
                if tuple(workspace.iterdir()):
                    executor.terminate_workers()
                    raise RuntimeError(f"fuzz input {index} leaked temporary artifacts")
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
            if previous_workspace is None:
                os.environ.pop(_WORKSPACE_ENVIRONMENT, None)
            else:
                os.environ[_WORKSPACE_ENVIRONMENT] = previous_workspace



#### Parse command arguments, execute the deterministic corpus budget, and return process status.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--deadline-seconds", type=float, default=1.0)
    arguments = parser.parse_args(argv)
    corpus_directory = cast(Path, arguments.corpus)
    iterations = cast(int, arguments.iterations)
    deadline_seconds = cast(float, arguments.deadline_seconds)
    if iterations < 1 or deadline_seconds <= 0:
        parser.error("iterations and deadline must be positive")
    try:
        corpus = _load_corpus(corpus_directory)
        _run(corpus, iterations, deadline_seconds)
    except (OSError, RuntimeError, ValueError):
        print("PasswordSafe fuzz run failed")
        return 1
    print(f"PasswordSafe fuzz inputs={iterations} corpus={len(corpus)}")
    return 0



# Return the command status without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
