"""Fetch, verify, safely build, and locate the pinned Botan shared library.

The command stores its verified upstream source archive in the ignored Botan cache and installs only a minimized shared
library into an explicitly selected build output.  It never accepts a runtime download location or emits source paths.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import json
import platform
import shutil
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.request import urlopen



PIN_PATH = Path(__file__).with_name("botan-source.json")
TARGET_PROFILES: dict[str, tuple[str, ...]] = {
    "windows": ("--cc=msvc", "--os=windows", "--cpu=x86_64"),
    "macos": ("--cc=clang", "--os=darwin"),
    "linux": ("--cc=gcc", "--os=linux"),
    "android": ("--cc=clang", "--os=android", "--cpu=arm64"),
    "ios": ("--cc=clang", "--os=ios", "--cpu=arm64"),
}
FINAL_LIBRARY_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("bin", ("botan-3.dll", "libbotan-3.dll")),
    ("lib", ("libbotan-3.dylib", "libbotan-3.so*")),
)



#### Report an acquisition, archive, configuration, or compilation failure without sensitive input details.
####
class BotanBuildError(RuntimeError):
    pass



#### Represent the complete machine-readable identity of the approved Botan source archive.
####
@dataclass(frozen=True, slots=True)
class BotanSourcePin:
    version: str
    archive: str
    source: str
    signature: str
    sha256: str
    modules: tuple[str, ...]



#### Load and validate the exact pinned source-release fields used by the build boundary.
####
#### This function rejects malformed configuration before network or archive operations begin.  The pin is intentionally
#### local and versioned so release review can compare its source, signature URL, digest, and requested modules.
####
def load_source_pin(path: Path) -> BotanSourcePin:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BotanBuildError("Botan source pin is unavailable") from error
    if not isinstance(document, dict):
        raise BotanBuildError("Botan source pin is invalid")

    values = cast(dict[str, object], document)
    version = values.get("version")
    archive = values.get("archive")
    source = values.get("source")
    signature = values.get("signature")
    sha256 = values.get("sha256")
    modules = values.get("modules")
    if not all(isinstance(value, str) and value for value in (version, archive, source, signature, sha256)):
        raise BotanBuildError("Botan source pin is invalid")
    if not isinstance(modules, list) or not all(isinstance(module, str) and module for module in modules):
        raise BotanBuildError("Botan source pin is invalid")
    source_url = cast(str, source)
    signature_url = cast(str, signature)
    sha256_value = cast(str, sha256)
    module_names = cast(list[str], modules)
    if (
        len(set(module_names)) != len(module_names)
        or len(sha256_value) != 64
        or any(character not in "0123456789abcdef" for character in sha256_value)
        or not source_url.startswith("https://")
        or not signature_url.startswith("https://")
    ):
        raise BotanBuildError("Botan source pin is invalid")
    return BotanSourcePin(
        version=cast(str, version),
        archive=cast(str, archive),
        source=source_url,
        signature=signature_url,
        sha256=sha256_value,
        modules=tuple(module_names),
    )



#### Download the pinned archive once, then verify its exact SHA-256 before returning it.
####
#### The temporary name prevents a partial network response from becoming a cache hit.  A cached archive receives the
#### same constant-time checksum comparison, so corruption cannot bypass verification on subsequent builds.
####
def download_verified_archive(pin: BotanSourcePin, cache_directory: Path) -> Path:
    try:
        cache_directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise BotanBuildError("Botan cache preparation failed") from error
    destination = cache_directory / pin.archive
    if not destination.exists():
        temporary = destination.with_suffix(destination.suffix + ".partial")
        try:
            with urlopen(pin.source, timeout=60) as response, temporary.open("xb") as output:  # nosec B310
                shutil.copyfileobj(response, output, length=1024 * 1024)
            temporary.replace(destination)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise BotanBuildError("Botan archive download failed") from error
    try:
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    except OSError as error:
        raise BotanBuildError("Botan archive read failed") from error
    if not hmac.compare_digest(digest, pin.sha256):
        raise BotanBuildError("Botan archive checksum mismatch")
    return destination



#### Extract a verified archive only when every member remains inside the requested destination.
####
#### Python's data filter rejects unsafe metadata and links.  The explicit resolved-member check additionally makes the
#### parent-directory boundary visible in this build layer and supplies one stable error for malicious member names.
####
def extract_verified_archive(archive_path: Path, destination: Path) -> Path:
    try:
        destination.mkdir(parents=True, exist_ok=True)
        resolved_destination = destination.resolve()
        with tarfile.open(archive_path, "r:xz") as archive:
            for member in archive.getmembers():
                member_path = (resolved_destination / member.name).resolve()
                if not member_path.is_relative_to(resolved_destination):
                    raise BotanBuildError("unsafe archive member")



            #### Apply Python's secure data filter after the explicit destination check.
            ####
            def safe_member(member: tarfile.TarInfo, destination_name: str) -> tarfile.TarInfo | None:
                try:
                    return tarfile.data_filter(member, destination_name)
                except tarfile.FilterError as error:
                    raise BotanBuildError("unsafe archive member") from error



            archive.extractall(resolved_destination, filter=safe_member)  # nosec B202
    except (OSError, tarfile.TarError) as error:
        raise BotanBuildError("Botan archive extraction failed") from error
    return resolved_destination



#### Extract verified archive bytes into one fresh digest-bound directory owned by this build.
####
#### Extracted source trees are never reusable cache inputs because they can be partial, modified, or symlinked after a
#### previous build.  The temporary directory is unique and resides below the ignored cache.  It is removed after the
#### build.
####
@contextmanager
def extract_fresh_verified_source(
    archive_path: Path,
    pin: BotanSourcePin,
    cache_directory: Path,
) -> Iterator[Path]:
    try:
        cache_directory.mkdir(parents=True, exist_ok=True)
        temporary_source = tempfile.TemporaryDirectory(
            prefix=f"source-{pin.sha256}-",
            dir=cache_directory,
        )
    except OSError as error:
        raise BotanBuildError("Botan cache preparation failed") from error
    with temporary_source:
        extraction_directory = Path(temporary_source.name)
        extract_verified_archive(archive_path, extraction_directory)
        source_directory = extraction_directory / f"Botan-{pin.version}"
        try:
            resolved_source = source_directory.resolve()
        except OSError as error:
            raise BotanBuildError("Botan verified source is unavailable") from error
        if (
            not source_directory.is_dir()
            or source_directory.is_symlink()
            or not resolved_source.is_relative_to(extraction_directory)
        ):
            raise BotanBuildError("Botan archive does not contain the pinned source directory")
        yield source_directory



#### Return a Windows short path when Botan's NMake generator cannot safely consume spaces.
####
#### The Windows build tools are invoked only after the operating system resolves this existing path.  Other platforms
#### retain their original paths, and unavailable short names fail before Botan can emit a truncated dependency target.
####
def windows_toolchain_path(path: Path) -> Path:
    if platform.system() != "Windows":
        return path
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_short_path_name = kernel32.GetShortPathNameW
    get_short_path_name.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    get_short_path_name.restype = ctypes.c_uint32
    size = get_short_path_name(str(path), None, 0)
    if size == 0:
        raise BotanBuildError("Botan Windows toolchain path is unavailable")
    buffer = ctypes.create_unicode_buffer(size)
    result = get_short_path_name(str(path), buffer, size)
    if result == 0 or result >= size:
        raise BotanBuildError("Botan Windows toolchain path is unavailable")
    return Path(buffer.value)



#### Produce the required stable cross-platform Botan configure command.
####
#### The source directory is used as the command working directory; all generated build and installation output remains
#### under the explicitly supplied output directory.  The target profiles are part of the approved native ABI contract.
####
def configure_command(target: str, source_directory: Path, output_directory: Path) -> tuple[str, ...]:
    profile = TARGET_PROFILES.get(target)
    if profile is None:
        raise BotanBuildError("unsupported Botan build target")
    build_directory = output_directory / "work"
    return (
        sys.executable,
        str(source_directory / "configure.py"),
        f"--prefix={output_directory}",
        f"--with-build-dir={build_directory}",
        "--minimized-build",
        "--enable-modules=ffi,twofish",
        "--build-targets=shared",
        *profile,
    )



#### Resolve the current operating system to its approved Botan host profile name.
####
def host_target() -> str:
    system = platform.system()
    host_targets = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}
    target = host_targets.get(system)
    if target is None:
        raise BotanBuildError("unsupported Botan host platform")
    return target



#### Return the target-specific make invocation for a generated Botan build directory.
####
def build_command(target: str, build_directory: Path) -> tuple[str, ...]:
    makefile = build_directory / "Makefile"
    if target == "windows":
        return ("nmake", "/f", str(makefile), "install")
    return ("make", "-f", str(makefile), "install")



#### Locate the installed shared library without guessing at a generated staging file.
####
#### Botan's supported platform names vary by suffix and ABI suffix.  The search is deliberately restricted to the
#### installer's `bin` and `lib` tiers, excluding its generated `work` staging tree.  An absent or ambiguous final-tier
#### result remains an error rather than selecting an arbitrary library.
####
def find_shared_library(output_directory: Path) -> Path:
    try:
        candidates = tuple(
            path
            for directory, patterns in FINAL_LIBRARY_LOCATIONS
            for pattern in patterns
            for path in (output_directory / directory).glob(pattern)
            if path.is_file()
        )
    except OSError as error:
        raise BotanBuildError("Botan shared library discovery failed") from error
    if len(candidates) != 1:
        raise BotanBuildError("Botan shared library was not produced")
    return candidates[0]



#### Resolve caller-controlled CLI paths without leaking filesystem exceptions at the command boundary.
####
#### Path resolution can itself fail before the build starts.  Preserve the operating-system error as the typed cause
#### while exposing only one stable message to the command-line caller.
####
def resolve_cli_paths(output_directory: Path, cache_directory: Path) -> tuple[Path, Path]:
    try:
        return output_directory.resolve(), cache_directory.resolve()
    except OSError as error:
        raise BotanBuildError("Botan path preparation failed") from error



#### Build the verified source for one target and return its installed shared-library path.
####
#### The caller owns the output directory selection.  This routine keeps sources in the ignored cache, configures a
#### minimized shared build, suppresses compiler chatter, and reports a stable failure category if a tool exits nonzero.
####
def build_botan(target: str, output_directory: Path, cache_directory: Path) -> Path:
    pin = load_source_pin(PIN_PATH)
    archive_path = download_verified_archive(pin, cache_directory)
    with extract_fresh_verified_source(archive_path, pin, cache_directory) as source_directory:
        try:
            output_directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise BotanBuildError("Botan output directory preparation failed") from error
        toolchain_source_directory = windows_toolchain_path(source_directory)
        toolchain_output_directory = windows_toolchain_path(output_directory)
        command = configure_command(target, toolchain_source_directory, toolchain_output_directory)
        try:
            configure_result = subprocess.run(  # nosec B603
                command,
                cwd=toolchain_source_directory,
                capture_output=True,
                check=False,
                text=True,
            )
        except OSError as error:
            raise BotanBuildError("Botan configuration command is unavailable") from error
        if configure_result.returncode != 0:
            raise BotanBuildError("Botan configuration failed")
        try:
            compile_result = subprocess.run(  # nosec B603
                build_command(target, toolchain_output_directory / "work"),
                cwd=toolchain_source_directory,
                capture_output=True,
                check=False,
                text=True,
            )
        except OSError as error:
            raise BotanBuildError("Botan compilation command is unavailable") from error
        if compile_result.returncode != 0:
            raise BotanBuildError("Botan compilation failed")
        return find_shared_library(output_directory)



#### Parse command-line arguments, build the requested profile, and print only its library path and version.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("host", *TARGET_PROFILES), default="host")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path(".cache/botan"))
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        target_argument = cast(str, arguments.target)
        target = host_target() if target_argument == "host" else target_argument
        output_directory, cache_directory = resolve_cli_paths(
            cast(Path, arguments.output),
            cast(Path, arguments.cache),
        )
        library_path = build_botan(
            target,
            output_directory,
            cache_directory,
        )
    except BotanBuildError as error:
        print(error, file=sys.stderr)
        return 1
    pin = load_source_pin(PIN_PATH)
    github_output = cast(Path | None, arguments.github_output)
    if github_output is not None:
        try:
            with github_output.open("a", encoding="utf-8", newline="\n") as output_stream:
                output_stream.write(f"library={library_path}\n")
        except OSError:
            print("GitHub output publication failed", file=sys.stderr)
            return 1
    print(f"{library_path} Botan {pin.version}")
    return 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
