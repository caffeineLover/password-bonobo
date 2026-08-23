"""Fetch, verify, safely build, and locate the pinned Botan shared library.

The command stores its verified upstream source archive in the ignored Botan cache and installs only a minimized shared
library into an explicitly selected build output.  It never accepts a runtime download location or emits source paths.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import platform
import shutil
import subprocess  # nosec B404
import sys
import tarfile
from collections.abc import Sequence
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
    cache_directory.mkdir(parents=True, exist_ok=True)
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
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest, pin.sha256):
        raise BotanBuildError("Botan archive checksum mismatch")
    return destination



#### Extract a verified archive only when every member remains inside the requested destination.
####
#### Python's data filter rejects unsafe metadata and links.  The explicit resolved-member check additionally makes the
#### parent-directory boundary visible in this build layer and supplies one stable error for malicious member names.
####
def extract_verified_archive(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    resolved_destination = destination.resolve()
    try:
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



#### Locate the installed shared library without guessing at an arbitrary native file.
####
#### Botan's supported platform names vary by suffix and ABI suffix.  The search is deliberately limited to the selected
#### output directory and rejects an absent or ambiguous result instead of returning an unrelated library.
####
def find_shared_library(output_directory: Path) -> Path:
    candidates = tuple(
        path
        for pattern in ("botan-3.dll", "libbotan-3.dll", "libbotan-3.dylib", "libbotan-3.so*")
        for path in output_directory.rglob(pattern)
        if path.is_file()
    )
    if len(candidates) != 1:
        raise BotanBuildError("Botan shared library was not produced")
    return candidates[0]



#### Build the verified source for one target and return its installed shared-library path.
####
#### The caller owns the output directory selection.  This routine keeps sources in the ignored cache, configures a
#### minimized shared build, suppresses compiler chatter, and reports a stable failure category if a tool exits nonzero.
####
def build_botan(target: str, output_directory: Path, cache_directory: Path) -> Path:
    pin = load_source_pin(PIN_PATH)
    archive_path = download_verified_archive(pin, cache_directory)
    source_parent = cache_directory / "source"
    source_directory = source_parent / f"Botan-{pin.version}"
    if not source_directory.is_dir():
        extract_verified_archive(archive_path, source_parent)
    if not source_directory.is_dir():
        raise BotanBuildError("Botan archive does not contain the pinned source directory")

    output_directory.mkdir(parents=True, exist_ok=True)
    command = configure_command(target, source_directory, output_directory)
    try:
        configure_result = subprocess.run(  # nosec B603
            command,
            cwd=source_directory,
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
            build_command(target, output_directory / "work"),
            cwd=source_directory,
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
    arguments = parser.parse_args(argv)
    target_argument = cast(str, arguments.target)
    target = host_target() if target_argument == "host" else target_argument
    try:
        library_path = build_botan(
            target,
            cast(Path, arguments.output).resolve(),
            cast(Path, arguments.cache).resolve(),
        )
    except BotanBuildError as error:
        print(error, file=sys.stderr)
        return 1
    pin = load_source_pin(PIN_PATH)
    print(f"{library_path} Botan {pin.version}")
    return 0


# Return the command status to the invoking shell without configuring runtime logging.
if __name__ == "__main__":
    raise SystemExit(main())
