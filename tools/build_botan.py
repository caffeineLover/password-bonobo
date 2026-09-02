"""Fetch, verify, safely build, and locate the pinned Botan library.

The command stores its verified upstream source archive in the ignored Botan cache and installs a minimized host shared
library or mobile static archive into an explicitly selected build output. It never accepts a runtime download location
or emits source paths.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import json
import os
import platform
import re
import shlex
import shutil
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from urllib.request import urlopen



PIN_PATH = Path(__file__).with_name("botan-source.json")
TARGET_PROFILES: dict[str, tuple[str, ...]] = {
    "windows-x86_64": ("--cc=msvc", "--os=windows", "--cpu=x86_64"),
    "macos-arm64": ("--cc=clang", "--os=darwin", "--cpu=arm64"),
    "linux-x86_64": ("--cc=gcc", "--os=linux", "--cpu=x86_64"),
    "android-arm64": ("--cc=clang", "--os=android", "--cpu=arm64"),
    "ios-arm64": ("--cc=clang", "--os=ios", "--cpu=arm64"),
}
FINAL_LIBRARY_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("bin", ("botan-3.dll", "libbotan-3.dll")),
    ("lib", ("libbotan-3.dylib", "libbotan-3.so*")),
)
LINUX_SHARED_LIBRARY_NAME_PATTERN: re.Pattern[str] = re.compile(
    r"^libbotan-3\.so(?:\.[0-9]+){0,3}$"
)
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ExecutableFinder = Callable[..., str | None]
MOBILE_TARGETS = frozenset({"android-arm64", "ios-arm64"})
MAX_NATIVE_DIAGNOSTIC_CHARS: int = 2_048
MAX_NATIVE_ARTIFACTS: int = 8
NATIVE_ARTIFACT_TIERS: tuple[str, ...] = ("bin", "lib", "lib64", "work")
BOTAN_ARTIFACT_NAME_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:(?:lib)?botan-3\.(?:dll|lib)|libbotan-3\.a|libbotan-3\.so(?:\.[0-9]+){0,3}|"
    r"libbotan-3(?:\.[0-9]+){0,3}\.dylib)$"
)
BOTAN_FFI_SMOKE_SOURCE = """#include <botan/ffi.h>

int main(void) {
    botan_block_cipher_t cipher = 0;
    const uint8_t key[32] = {0};
    const uint8_t input[16] = {0};
    uint8_t output[16] = {0};
    if (botan_block_cipher_init(&cipher, "Twofish") != 0) {
        return 1;
    }
    if (botan_block_cipher_set_key(cipher, key, sizeof(key)) != 0) {
        botan_block_cipher_destroy(cipher);
        return 2;
    }
    if (botan_block_cipher_encrypt_blocks(cipher, input, output, 1) != 0) {
        botan_block_cipher_destroy(cipher);
        return 3;
    }
    return botan_block_cipher_destroy(cipher) == 0 ? 0 : 4;
}
"""



#### Describe the Windows-only ctypes loader used to obtain the short-path API.
####
class _WindowsCtypesApi(Protocol):
    WinDLL: type[ctypes.CDLL]



_WINDOWS_CTYPES = cast(_WindowsCtypesApi, ctypes)



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



#### Append bounded native output to one stable failure category after redacting known private paths.
####
#### Configure, compiler, and linker diagnostics describe only the fixed public Botan build.  Path replacement occurs
#### before tail selection so a truncation boundary cannot reveal a partial source, output, SDK, or toolchain path.
#### Terminal control bytes are discarded before the text crosses the command-line boundary.
####
def _native_failure_message(
    category: str,
    result: subprocess.CompletedProcess[str],
    private_paths: Sequence[Path],
) -> str:
    diagnostic = "\n".join(part.strip() for part in (result.stdout or "", result.stderr or "") if part.strip())
    if not diagnostic:
        return category
    diagnostic = diagnostic.replace("\r\n", "\n").replace("\r", "\n")
    variants = {
        variant
        for path in private_paths
        for variant in (str(path), path.as_posix(), str(path).replace("\\", "/"), str(path).replace("/", "\\"))
        if variant
    }
    flags = re.IGNORECASE if platform.system() == "Windows" else 0
    for variant in sorted(variants, key=len, reverse=True):
        diagnostic = re.sub(re.escape(variant), "<redacted-path>", diagnostic, flags=flags)
    diagnostic = "".join(
        character
        for character in diagnostic
        if character == "\n" or 32 <= ord(character) < 127
    ).strip()
    if not diagnostic:
        return category
    return f"{category}\n{diagnostic[-MAX_NATIVE_DIAGNOSTIC_CHARS:]}"



#### Extract only absolute compiler and ABI paths from one validated target-toolchain option sequence.
####
#### The target resolvers construct these options from resolved paths.  Ignoring non-path flags prevents ordinary
#### compiler words such as `make` or `arm64` from being removed from actionable native diagnostics.
####
def _toolchain_private_paths(toolchain_options: Sequence[str]) -> tuple[Path, ...]:
    private_paths: list[Path] = []
    for option in toolchain_options:
        arguments: tuple[str, ...] = ()
        if option.startswith("--cc-bin="):
            arguments = (option.removeprefix("--cc-bin="),)
        elif option.startswith("--cc-abi-flags="):
            try:
                arguments = tuple(shlex.split(option.removeprefix("--cc-abi-flags=")))
            except ValueError:
                continue
        private_paths.extend(Path(argument) for argument in arguments if Path(argument).is_absolute())
    return tuple(private_paths)



#### Return a bounded relative inventory of Botan artifacts from fixed build and installation tiers.
####
#### Only conservative Botan-like basenames are retained.  Unrelated caller-controlled filenames and the absolute
#### output directory never cross the diagnostic boundary.
####
def _native_artifact_evidence(output_directory: Path) -> tuple[str, ...]:
    evidence: set[str] = set()
    try:
        for tier in NATIVE_ARTIFACT_TIERS:
            for path in (output_directory / tier).glob("*botan-3*"):
                name = path.name
                if (
                    len(name) <= 128
                    and BOTAN_ARTIFACT_NAME_PATTERN.fullmatch(name) is not None
                    and (path.is_file() or path.is_symlink())
                ):
                    evidence.add(f"{tier}/{name}")
    except OSError:
        return ()
    return tuple(sorted(evidence)[:MAX_NATIVE_ARTIFACTS])



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
    kernel32 = _WINDOWS_CTYPES.WinDLL("kernel32", use_last_error=True)
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



#### Return an isolated MSVC developer environment discovered through Visual Studio Installer.
####
#### Normal PowerShell and hosted-runner processes do not inherit compiler variables. The fixed vswhere query selects
#### the newest installation with the x64 C++ toolchain, and VsDevCmd initializes only the child NMake environment.
####
def windows_msvc_environment(
    *,
    environment: Mapping[str, str] | None = None,
    runner: CommandRunner = subprocess.run,
) -> dict[str, str]:
    selected_environment = os.environ if environment is None else environment
    program_files = selected_environment.get("ProgramFiles(x86)", "")
    if not program_files:
        raise BotanBuildError("MSVC developer environment is unavailable")
    try:
        vswhere = (
            Path(program_files)
            / "Microsoft Visual Studio"
            / "Installer"
            / "vswhere.exe"
        ).resolve()
    except OSError as error:
        raise BotanBuildError("MSVC developer environment is unavailable") from error
    if not vswhere.is_file():
        raise BotanBuildError("MSVC developer environment is unavailable")
    query = (
        str(vswhere),
        "-latest",
        "-products",
        "*",
        "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "-property",
        "installationPath",
    )
    try:
        query_result = runner(
            query,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as error:
        raise BotanBuildError("MSVC developer environment is unavailable") from error
    installations = tuple(line.strip() for line in query_result.stdout.splitlines() if line.strip())
    if query_result.returncode != 0 or len(installations) != 1:
        raise BotanBuildError("MSVC developer environment is unavailable")
    try:
        developer_command = (
            Path(installations[0]) / "Common7" / "Tools" / "VsDevCmd.bat"
        ).resolve()
    except OSError as error:
        raise BotanBuildError("MSVC developer environment is unavailable") from error
    if not developer_command.is_file():
        raise BotanBuildError("MSVC developer environment is unavailable")
    initialize = (
        "cmd.exe",
        "/d",
        "/c",
        str(developer_command),
        "-no_logo",
        "-arch=x64",
        "-host_arch=x64",
        "&&",
        "set",
    )
    try:
        environment_result = runner(
            initialize,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as error:
        raise BotanBuildError("MSVC developer environment is unavailable") from error
    if environment_result.returncode != 0:
        raise BotanBuildError("MSVC developer environment is unavailable")
    resolved_environment = dict(selected_environment)
    for line in environment_result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            resolved_environment[key] = value
    casefolded = {key.casefold(): value for key, value in resolved_environment.items()}
    for required in ("PATH", "INCLUDE", "LIB"):
        value = casefolded.get(required.casefold(), "")
        if not value:
            raise BotanBuildError("MSVC developer environment is unavailable")
        resolved_environment[required] = value
    return resolved_environment



#### Resolve NMake against the child developer PATH before CreateProcess starts.
####
#### Windows executable lookup occurs in the parent process before the child replacement environment is active, so an
#### absolute verified tool path is required even though the developer PATH is also passed to the compiler process.
####
def resolve_windows_nmake(
    environment: Mapping[str, str],
    *,
    executable_finder: ExecutableFinder = shutil.which,
) -> Path:
    found = executable_finder("nmake", path=environment.get("PATH", ""))
    if not found:
        raise BotanBuildError("Botan compilation command is unavailable")
    try:
        nmake = Path(found).resolve()
    except OSError as error:
        raise BotanBuildError("Botan compilation command is unavailable") from error
    if not nmake.is_file():
        raise BotanBuildError("Botan compilation command is unavailable")
    return nmake



#### Produce the required stable cross-platform Botan configure command.
####
#### The source directory is used as the command working directory; all generated build and installation output remains
#### under the explicitly supplied output directory.  The target profiles are part of the approved native ABI contract.
####
def configure_command(
    target: str,
    source_directory: Path,
    output_directory: Path,
    *,
    toolchain_options: Sequence[str] = (),
) -> tuple[str, ...]:
    profile = TARGET_PROFILES.get(target)
    if profile is None:
        raise BotanBuildError("unsupported Botan build target")
    build_directory = output_directory / "work"
    build_target = "static" if target in MOBILE_TARGETS else "shared"
    return (
        sys.executable,
        str(source_directory / "configure.py"),
        f"--prefix={output_directory}",
        f"--with-build-dir={build_directory}",
        "--minimized-build",
        "--enable-modules=ffi,twofish",
        f"--build-targets={build_target}",
        *profile,
        *toolchain_options,
    )



#### Resolve target-specific cross-compilers before any source acquisition or extraction.
####
#### Host profiles use the runner's normal compiler lookup. Android binds API 28 to the NDK's exact arm64 compiler;
#### iOS accepts only Xcode's iPhoneOS clang and SDK as reported by fixed xcrun commands on macOS.
####
def resolve_target_toolchain(
    target: str,
    *,
    environment: Mapping[str, str] | None = None,
    system: str | None = None,
    runner: CommandRunner = subprocess.run,
) -> tuple[str, ...]:
    if target not in TARGET_PROFILES:
        raise BotanBuildError("unsupported Botan build target")
    selected_environment = os.environ if environment is None else environment
    selected_system = platform.system() if system is None else system
    if target == "android-arm64":
        ndk_value = selected_environment.get("ANDROID_NDK_ROOT", "")
        host_tags = {
            "Windows": "windows-x86_64",
            "Darwin": "darwin-x86_64",
            "Linux": "linux-x86_64",
        }
        host_tag = host_tags.get(selected_system)
        if not ndk_value or host_tag is None:
            raise BotanBuildError("Android NDK toolchain is unavailable")
        try:
            compiler = (
                Path(ndk_value)
                / "toolchains"
                / "llvm"
                / "prebuilt"
                / host_tag
                / "bin"
                / "aarch64-linux-android28-clang++"
            ).resolve()
        except OSError as error:
            raise BotanBuildError("Android NDK toolchain is unavailable") from error
        if not compiler.is_file():
            raise BotanBuildError("Android NDK toolchain is unavailable")
        return (f"--cc-bin={compiler}",)
    if target != "ios-arm64":
        return ()
    if selected_system != "Darwin":
        raise BotanBuildError("iOS toolchain requires macOS")

    commands = (
        ("xcrun", "--sdk", "iphoneos", "--find", "clang++"),
        ("xcrun", "--sdk", "iphoneos", "--show-sdk-path"),
    )
    outputs: list[str] = []
    for command in commands:
        try:
            result = runner(command, capture_output=True, check=False, text=True)
        except OSError as error:
            raise BotanBuildError("iOS toolchain is unavailable") from error
        output = result.stdout.strip()
        if result.returncode != 0 or not output:
            raise BotanBuildError("iOS toolchain is unavailable")
        outputs.append(output)
    try:
        compiler = Path(outputs[0]).resolve()
        sdk = Path(outputs[1]).resolve()
    except OSError as error:
        raise BotanBuildError("iOS toolchain is unavailable") from error
    if not compiler.is_file() or not sdk.is_dir():
        raise BotanBuildError("iOS toolchain is unavailable")
    return (
        f"--cc-bin={compiler}",
        f"--cc-abi-flags={shlex.join(('-isysroot', str(sdk), '-arch', 'arm64'))}",
    )



#### Compile and link a foreign-architecture C probe without attempting to execute it.
####
#### The probe proves the installed headers and exact library expose the approved raw Twofish FFI. The compiler and
#### optional ABI flags must come from the already validated target-toolchain result, not a second ambient lookup.
####
def link_mobile_smoke_program(
    target: str,
    output_directory: Path,
    library_path: Path,
    toolchain_options: Sequence[str],
    *,
    runner: CommandRunner = subprocess.run,
) -> Path:
    if target not in MOBILE_TARGETS:
        raise BotanBuildError("mobile smoke target is unsupported")
    compiler_values = tuple(
        option.removeprefix("--cc-bin=")
        for option in toolchain_options
        if option.startswith("--cc-bin=")
    )
    abi_values = tuple(
        option.removeprefix("--cc-abi-flags=")
        for option in toolchain_options
        if option.startswith("--cc-abi-flags=")
    )
    if len(compiler_values) != 1 or len(abi_values) > 1:
        raise BotanBuildError("mobile smoke toolchain is invalid")
    compiler = Path(compiler_values[0])
    include_directory = output_directory / "include" / "botan-3"
    if not compiler.is_file() or not library_path.is_file() or not include_directory.is_dir():
        raise BotanBuildError("mobile smoke inputs are unavailable")
    try:
        abi_arguments = tuple(shlex.split(abi_values[0])) if abi_values else ()
    except ValueError as error:
        raise BotanBuildError("mobile smoke toolchain is invalid") from error

    smoke_directory = output_directory / "smoke"
    source_path = smoke_directory / "botan-ffi-smoke.c"
    linked_path = smoke_directory / "botan-ffi-smoke"
    try:
        smoke_directory.mkdir(parents=True, exist_ok=True)
        source_path.write_text(BOTAN_FFI_SMOKE_SOURCE, encoding="utf-8", newline="\n")
    except OSError as error:
        raise BotanBuildError("mobile smoke preparation failed") from error
    runtime_libraries = ("-lc++",) if target == "ios-arm64" else ()
    command = (
        str(compiler),
        *abi_arguments,
        "-std=c11",
        f"-I{include_directory}",
        "-x",
        "c",
        str(source_path),
        "-x",
        "none",
        str(library_path),
        *runtime_libraries,
        "-o",
        str(linked_path),
    )
    try:
        result = runner(
            command,
            cwd=smoke_directory,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as error:
        raise BotanBuildError("mobile smoke compiler is unavailable") from error
    if result.returncode != 0 or not linked_path.is_file():
        raise BotanBuildError(
            _native_failure_message(
                "mobile smoke link failed",
                result,
                (
                    compiler,
                    output_directory,
                    include_directory,
                    source_path,
                    library_path,
                    linked_path,
                    *_toolchain_private_paths(toolchain_options),
                ),
            )
        )
    return linked_path



#### Resolve the current operating system to its approved Botan host profile name.
####
def host_target() -> str:
    system = platform.system()
    machine = platform.machine().casefold()
    host_targets = {
        ("Windows", "amd64"): "windows-x86_64",
        ("Windows", "x86_64"): "windows-x86_64",
        ("Darwin", "arm64"): "macos-arm64",
        ("Linux", "x86_64"): "linux-x86_64",
        ("Linux", "amd64"): "linux-x86_64",
    }
    target = host_targets.get((system, machine))
    if target is None:
        if system not in {"Windows", "Darwin", "Linux"}:
            raise BotanBuildError("unsupported Botan host platform")
        raise BotanBuildError("unsupported Botan host architecture")
    return target



#### Return the target-specific make invocation for a generated Botan build directory.
####
def build_command(target: str, build_directory: Path) -> tuple[str, ...]:
    makefile = build_directory / "Makefile"
    if target == "windows-x86_64":
        return ("nmake", "/f", str(makefile), "install")
    return ("make", "-f", str(makefile), "install")



#### Locate the installed shared library without guessing at a generated staging file.
####
#### Botan's supported platform names vary by suffix and ABI suffix.  The search is deliberately restricted to the
#### installer's `bin` and `lib` tiers, excluding its generated `work` staging tree.  Linux's unversioned linker name
#### wins only when every other match is a numeric soname companion in the same directory.  Any other absent or
#### ambiguous final-tier result remains an error rather than selecting an arbitrary library.
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
    selected_candidates = candidates
    linux_linker_candidates = tuple(path for path in candidates if path.name == "libbotan-3.so")
    if len(linux_linker_candidates) == 1:
        linux_linker = linux_linker_candidates[0]
        if all(
            path.parent == linux_linker.parent
            and LINUX_SHARED_LIBRARY_NAME_PATTERN.fullmatch(path.name) is not None
            for path in candidates
        ):
            selected_candidates = linux_linker_candidates
    if len(selected_candidates) != 1:
        evidence = _native_artifact_evidence(output_directory)
        suffix = f"; observed Botan artifacts: {', '.join(evidence)}" if evidence else ""
        raise BotanBuildError(f"Botan shared library was not produced{suffix}")
    return selected_candidates[0]



#### Locate the single installed static archive used only by mobile link gates.
####
def find_static_library(output_directory: Path) -> Path:
    try:
        candidates = tuple(
            path
            for path in (output_directory / "lib").glob("libbotan-3.a")
            if path.is_file()
        )
    except OSError as error:
        raise BotanBuildError("Botan static library discovery failed") from error
    if len(candidates) != 1:
        raise BotanBuildError("Botan static library was not produced")
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



#### Build the verified source for one target and return its installed library path.
####
#### The caller owns the output directory selection.  This routine keeps sources in the ignored cache, configures a
#### minimized host-shared or mobile-static build and reports a stable failure category plus bounded path-redacted
#### native evidence if a tool exits nonzero.
####
def build_botan(
    target: str,
    output_directory: Path,
    cache_directory: Path,
    *,
    smoke_link: bool = False,
) -> Path:
    if smoke_link and target not in MOBILE_TARGETS:
        raise BotanBuildError("mobile smoke target is unsupported")
    toolchain_options = resolve_target_toolchain(target)
    toolchain_private_paths = _toolchain_private_paths(toolchain_options)
    pin = load_source_pin(PIN_PATH)
    archive_path = download_verified_archive(pin, cache_directory)
    with extract_fresh_verified_source(archive_path, pin, cache_directory) as source_directory:
        try:
            output_directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise BotanBuildError("Botan output directory preparation failed") from error
        toolchain_source_directory = windows_toolchain_path(source_directory)
        toolchain_output_directory = windows_toolchain_path(output_directory)
        command = configure_command(
            target,
            toolchain_source_directory,
            toolchain_output_directory,
            toolchain_options=toolchain_options,
        )
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
            raise BotanBuildError(
                _native_failure_message(
                    "Botan configuration failed",
                    configure_result,
                    (
                        cache_directory,
                        source_directory,
                        toolchain_source_directory,
                        output_directory,
                        toolchain_output_directory,
                        Path(sys.executable),
                        *toolchain_private_paths,
                    ),
                )
            )
        compile_command = build_command(target, toolchain_output_directory / "work")
        compile_environment = None
        if target == "windows-x86_64":
            compile_environment = windows_msvc_environment()
            nmake = resolve_windows_nmake(compile_environment)
            compile_command = (str(nmake), *compile_command[1:])
        try:
            compile_result = subprocess.run(  # nosec B603
                compile_command,
                cwd=toolchain_source_directory,
                capture_output=True,
                check=False,
                env=compile_environment,
                text=True,
            )
        except OSError as error:
            raise BotanBuildError("Botan compilation command is unavailable") from error
        if compile_result.returncode != 0:
            compile_executable = Path(compile_command[0])
            compile_executable_paths = (compile_executable,) if compile_executable.is_absolute() else ()
            raise BotanBuildError(
                _native_failure_message(
                    "Botan compilation failed",
                    compile_result,
                    (
                        cache_directory,
                        source_directory,
                        toolchain_source_directory,
                        output_directory,
                        toolchain_output_directory,
                        *toolchain_private_paths,
                        *compile_executable_paths,
                    ),
                )
            )
        library_path = (
            find_static_library(output_directory)
            if target in MOBILE_TARGETS
            else find_shared_library(output_directory)
        )
        if smoke_link:
            link_mobile_smoke_program(
                target,
                output_directory,
                library_path,
                toolchain_options,
            )
        return library_path



#### Parse command-line arguments, build the requested profile, and print only its library path and version.
####
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("host", *TARGET_PROFILES), default="host")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path(".cache/botan"))
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--smoke-link", action="store_true")
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
            smoke_link=cast(bool, arguments.smoke_link),
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
