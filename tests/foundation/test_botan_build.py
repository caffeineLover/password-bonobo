"""Verify the verified Botan source pin, archive extraction boundary, and build profiles."""

from __future__ import annotations

import hashlib
import io
import json
import platform
import shlex
import subprocess
import tarfile
from pathlib import Path

import pytest
import tools.build_botan as botan_build
from tools.build_botan import (
    BotanBuildError,
    BotanSourcePin,
    build_botan,
    configure_command,
    extract_fresh_verified_source,
    extract_verified_archive,
    find_shared_library,
    load_source_pin,
    main,
    windows_toolchain_path,
)



REPOSITORY_ROOT = Path(__file__).parents[2]



#### Create a small xz-compressed archive with exact synthetic member payloads.
####
#### The helper keeps archive construction in the test boundary so extraction tests
#### exercise the production tar-file validation rather than a mocked archive API.
####
def create_tar_xz(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:xz") as archive:
        for name, payload in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return path



#### Build a complete synthetic source pin for a local archive without network behavior.
####
#### Tests use this independent digest to confirm that cache selection follows the
#### verified archive bytes rather than an existing extracted-source directory.
####
def source_pin_for_archive(archive: Path) -> BotanSourcePin:
    return BotanSourcePin(
        version="3.13.0",
        archive=archive.name,
        source="https://example.invalid/Botan-3.13.0.tar.xz",
        signature="https://example.invalid/Botan-3.13.0.tar.xz.asc",
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        modules=("ffi", "twofish"),
    )



#### Write one valid source-pin document for a controlled local build setup.
####
#### This helper only redirects the module's pin lookup in the output-directory
#### failure test; archive extraction and all filesystem operations stay real.
####
def write_source_pin(path: Path, pin: BotanSourcePin) -> None:
    path.write_text(
        json.dumps(
            {
                "archive": pin.archive,
                "modules": list(pin.modules),
                "sha256": pin.sha256,
                "signature": pin.signature,
                "source": pin.source,
                "version": pin.version,
            }
        ),
        encoding="utf-8",
    )



#### Preserve the approved Botan release identity and required minimized modules.
####
#### A changed version, digest, or module selection would make the resulting native
#### build ineligible for the approved production Twofish boundary.
####
def test_botan_source_pin_matches_approved_release() -> None:
    pin = load_source_pin(REPOSITORY_ROOT / "tools" / "botan-source.json")

    assert pin.version == "3.13.0"
    assert pin.sha256 == "12f5a8358890bbee82edfe9d2e7769b0a610b6dd0e0698aea13d20a675d84620"
    assert pin.modules == ("ffi", "twofish")



#### Reject a source pin that could direct verified acquisition to a local or non-HTTPS scheme.
####
#### The pin is repository-controlled, but restricting its endpoint to HTTPS keeps a
#### malformed review update from widening the build tool's URL-opening capability.
####
def test_botan_source_pin_rejects_non_https_source(tmp_path: Path) -> None:
    malformed_pin = tmp_path / "botan-source.json"
    source = (REPOSITORY_ROOT / "tools" / "botan-source.json").read_text(encoding="utf-8")
    malformed_pin.write_text(source.replace("https://", "file://", 1), encoding="utf-8")

    with pytest.raises(BotanBuildError, match="Botan source pin is invalid"):
        load_source_pin(malformed_pin)



#### Refuse an archive member that would escape the dedicated extraction directory.
####
#### An untrusted upstream archive must never be able to overwrite a neighboring
#### checkout file through a parent-directory traversal member name.
####
def test_extract_rejects_parent_escape(tmp_path: Path) -> None:
    archive = create_tar_xz(tmp_path / "bad.tar.xz", {"../outside": b"forbidden"})

    with pytest.raises(BotanBuildError, match="unsafe archive member"):
        extract_verified_archive(archive, tmp_path / "output")



#### Re-extract verified bytes into a fresh digest-bound directory despite a poisoned old cache.
####
#### A reused extracted tree can contain partial, modified, or symlinked files even
#### when the cached archive is valid, so compilation must receive only fresh bytes.
####
def test_fresh_verified_source_ignores_poisoned_extraction_cache(tmp_path: Path) -> None:
    archive = create_tar_xz(
        tmp_path / "Botan-3.13.0.tar.xz",
        {"Botan-3.13.0/configure.py": b"verified configure source"},
    )
    pin = source_pin_for_archive(archive)
    cache_directory = tmp_path / "cache"
    poisoned_source = cache_directory / "source" / "Botan-3.13.0"
    poisoned_source.mkdir(parents=True)
    (poisoned_source / "configure.py").write_bytes(b"poisoned configure source")

    with extract_fresh_verified_source(archive, pin, cache_directory) as source_directory:
        assert source_directory != poisoned_source
        assert source_directory.parent.name.startswith(f"source-{pin.sha256}-")
        assert (source_directory / "configure.py").read_bytes() == b"verified configure source"

    assert not source_directory.parent.exists()



#### Translate an unusable extraction destination into the build failure taxonomy.
####
#### A filesystem object at the destination prevents directory creation.  The caller
#### must receive a concise typed failure instead of the platform's path-bearing error.
####
def test_extract_reports_destination_creation_failure(tmp_path: Path) -> None:
    archive = create_tar_xz(tmp_path / "good.tar.xz", {"Botan-3.13.0/configure.py": b"safe"})
    destination = tmp_path / "not-a-directory"
    destination.write_text("blocking file", encoding="utf-8")

    with pytest.raises(BotanBuildError, match="Botan archive extraction failed"):
        extract_verified_archive(archive, destination)



#### Report a cache-directory creation failure through the CLI without a traceback or path.
####
#### The command boundary catches expected typed build failures and must never leak a
#### caller-selected cache path when the filesystem rejects directory creation.
####
def test_main_reports_cache_creation_failure_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cache_path = tmp_path / "not-a-directory"
    cache_path.write_text("blocking file", encoding="utf-8")

    result = main(["--target", "host", "--output", str(tmp_path / "output"), "--cache", str(cache_path)])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == "Botan cache preparation failed\n"
    assert str(cache_path) not in captured.err
    assert "Traceback" not in captured.err



#### Publish the resolved host library through GitHub's file-based output protocol.
####
def test_main_writes_github_output_library(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    library = (tmp_path / "output" / "lib" / "libbotan-3.so").resolve()
    library.parent.mkdir(parents=True)
    library.write_bytes(b"synthetic shared library")
    github_output = tmp_path / "github-output.txt"
    monkeypatch.setattr(
        botan_build,
        "build_botan",
        lambda *_arguments, **_keywords: library,
    )

    result = main(
        [
            "--target",
            "host",
            "--output",
            str(tmp_path / "output"),
            "--github-output",
            str(github_output),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == f"{library} Botan 3.13.0\n"
    assert captured.err == ""
    assert github_output.read_text(encoding="utf-8") == f"library={library}\n"



#### Translate output-directory creation failure before configuring the verified source.
####
#### The output boundary is caller selected.  A blocking file must produce a typed
#### failure and never advance to compiler execution with an ambiguous output location.
####
def test_build_reports_output_creation_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_directory = tmp_path / "cache"
    cache_directory.mkdir()
    archive = create_tar_xz(
        cache_directory / "Botan-3.13.0.tar.xz",
        {"Botan-3.13.0/configure.py": b"verified configure source"},
    )
    pin = source_pin_for_archive(archive)
    pin_path = tmp_path / "botan-source.json"
    write_source_pin(pin_path, pin)
    monkeypatch.setattr(botan_build, "PIN_PATH", pin_path)
    output_directory = tmp_path / "not-a-directory"
    output_directory.write_text("blocking file", encoding="utf-8")

    with pytest.raises(BotanBuildError, match="Botan output directory preparation failed"):
        build_botan("linux-x86_64", output_directory, cache_directory)



#### Select the installed library when the generated build tree retains an identical staging copy.
####
#### Botan installs the Windows deliverable below `bin` but leaves a byte-identical
#### build-stage DLL below `work`.  Discovery must select the installed deliverable
#### deterministically rather than treating normal build output as ambiguous.
####
def test_find_shared_library_prefers_installed_library_over_staging_copy(tmp_path: Path) -> None:
    output_directory = tmp_path / "botan-output"
    final_library = output_directory / "bin" / "botan-3.dll"
    staging_library = output_directory / "work" / "botan-3.dll"
    final_library.parent.mkdir(parents=True)
    staging_library.parent.mkdir(parents=True)
    final_library.write_bytes(b"installed")
    staging_library.write_bytes(b"staging")

    assert find_shared_library(output_directory) == final_library



#### Refuse an ambiguous installed-library tier instead of choosing a final file by traversal order.
####
#### An output with two matching files below `bin` is corrupt or incomplete.  The
#### staging exclusion must not weaken the original ambiguity rejection contract.
####
def test_find_shared_library_rejects_ambiguous_installed_tier(tmp_path: Path) -> None:
    bin_directory = tmp_path / "botan-output" / "bin"
    bin_directory.mkdir(parents=True)
    (bin_directory / "botan-3.dll").write_bytes(b"first")
    (bin_directory / "libbotan-3.dll").write_bytes(b"second")

    with pytest.raises(BotanBuildError, match="Botan shared library was not produced"):
        find_shared_library(bin_directory.parent)



#### Keep caller-controlled paths inside the CLI's typed failure boundary during resolution.
####
#### A resolving filesystem error contains the rejected input path.  The command
#### must instead emit a concise build error without a traceback or that path.
####
def test_main_hides_output_resolution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_path = tmp_path / "unresolvable output"
    original_resolve = Path.resolve



    #### Raise the platform-style error only for the caller-controlled output path.
    ####
    #### Other path resolutions use the original standard-library implementation so
    #### this regression isolates the command boundary under test.
    ####
    def reject_output_resolution(path: Path, strict: bool = False) -> Path:
        if path == output_path:
            raise OSError(f"cannot resolve {path}")
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", reject_output_resolution)

    result = main(["--target", "host", "--output", str(output_path)])

    captured = capsys.readouterr()
    assert result == 1
    assert captured.out == ""
    assert captured.err == "Botan path preparation failed\n"
    assert str(output_path) not in captured.err
    assert "Traceback" not in captured.err



#### Convert an existing Windows build path with spaces before handing it to NMake tooling.
####
#### Botan's generated NMake dependencies do not quote repository paths reliably,
#### so the Windows boundary must use the operating system's equivalent short path.
####
@pytest.mark.skipif(platform.system() != "Windows", reason="Windows short paths are platform specific")
def test_windows_toolchain_path_removes_spaces(tmp_path: Path) -> None:
    source_directory = tmp_path / "source with spaces"
    source_directory.mkdir()

    converted_path = windows_toolchain_path(source_directory)

    assert converted_path.is_dir()
    assert " " not in str(converted_path)



#### Import the installed MSVC developer environment without mutating the parent process.
####
def test_windows_msvc_environment_uses_verified_visual_studio_tools(tmp_path: Path) -> None:
    program_files = tmp_path / "Program Files (x86)"
    vswhere = program_files / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    installation = tmp_path / "Microsoft Visual Studio" / "18" / "Community"
    developer_command = installation / "Common7" / "Tools" / "VsDevCmd.bat"
    vswhere.parent.mkdir(parents=True)
    vswhere.write_bytes(b"synthetic vswhere")
    developer_command.parent.mkdir(parents=True)
    developer_command.write_bytes(b"synthetic developer command")
    commands: list[tuple[str, ...]] = []



    #### Record Visual Studio environment-discovery commands and return fixtures.
    ####
    def run_command(
        command: tuple[str, ...],
        **_arguments: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = (
            f"{installation}\n"
            if command[0] == str(vswhere)
            else "Path=C:\\synthetic\\msvc\nINCLUDE=C:\\synthetic\\include\nLIB=C:\\synthetic\\lib\n"
        )
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    resolved = botan_build.windows_msvc_environment(
        environment={"ProgramFiles(x86)": str(program_files), "SYSTEMROOT": "C:\\Windows"},
        runner=run_command,
    )

    assert resolved["PATH"] == "C:\\synthetic\\msvc"
    assert resolved["INCLUDE"] == "C:\\synthetic\\include"
    assert resolved["LIB"] == "C:\\synthetic\\lib"
    assert commands[0][0] == str(vswhere)
    assert str(developer_command) in commands[1]



#### Reject an incomplete developer environment before invoking NMake.
####
def test_windows_msvc_environment_requires_compile_and_link_paths(tmp_path: Path) -> None:
    program_files = tmp_path / "Program Files (x86)"
    vswhere = program_files / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    installation = tmp_path / "Visual Studio"
    developer_command = installation / "Common7" / "Tools" / "VsDevCmd.bat"
    vswhere.parent.mkdir(parents=True)
    vswhere.write_bytes(b"synthetic vswhere")
    developer_command.parent.mkdir(parents=True)
    developer_command.write_bytes(b"synthetic developer command")



    #### Return an incomplete Visual Studio developer environment fixture.
    ####
    def run_command(
        command: tuple[str, ...],
        **_arguments: object,
    ) -> subprocess.CompletedProcess[str]:
        stdout = f"{installation}\n" if command[0] == str(vswhere) else "Path=C:\\synthetic\\msvc\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    with pytest.raises(BotanBuildError, match="MSVC developer environment is unavailable"):
        botan_build.windows_msvc_environment(
            environment={"ProgramFiles(x86)": str(program_files)},
            runner=run_command,
        )



#### Resolve NMake explicitly because CreateProcess does not search the child's replacement PATH.
####
def test_windows_nmake_resolution_uses_developer_environment_path(tmp_path: Path) -> None:
    nmake = tmp_path / "Visual Studio" / "nmake.exe"
    nmake.parent.mkdir(parents=True)
    nmake.write_bytes(b"synthetic nmake")
    calls: list[tuple[str, str | None]] = []



    #### Record the executable lookup and return the synthetic nmake path.
    ####
    def find_executable(name: str, *, path: str | None = None) -> str | None:
        calls.append((name, path))
        return str(nmake)

    resolved = botan_build.resolve_windows_nmake(
        {"PATH": "C:\\synthetic\\msvc"},
        executable_finder=find_executable,
    )

    assert resolved == nmake
    assert calls == [("nmake", "C:\\synthetic\\msvc")]



#### Generate the approved compiler, operating-system, and CPU profile for every target.
####
#### A profile substitution can silently produce an unusable binary or omit the
#### intended platform architecture, so each configured target is asserted literally.
####
@pytest.mark.parametrize(
    ("target", "expected_profile"),
    (
        ("windows-x86_64", ("--cc=msvc", "--os=windows", "--cpu=x86_64")),
        ("macos-arm64", ("--cc=clang", "--os=darwin", "--cpu=arm64")),
        ("linux-x86_64", ("--cc=gcc", "--os=linux", "--cpu=x86_64")),
        ("android-arm64", ("--cc=clang", "--os=android", "--cpu=arm64")),
        ("ios-arm64", ("--cc=clang", "--os=ios", "--cpu=arm64")),
    ),
)
def test_configure_command_uses_approved_target_profile(
    target: str,
    expected_profile: tuple[str, ...],
) -> None:
    command = configure_command(
        target,
        Path("C:/synthetic/botan-source"),
        Path("C:/synthetic/botan-output"),
    )

    assert all(option in command for option in expected_profile)
    assert "--minimized-build" in command
    assert "--enable-modules=ffi,twofish" in command
    expected_build_target = (
        "--build-targets=static"
        if target in {"android-arm64", "ios-arm64"}
        else "--build-targets=shared"
    )
    assert expected_build_target in command
    assert not any("tls" in argument for argument in command)



#### Select the one installed static archive used by mobile link smoke gates.
####
def test_find_static_library_selects_installed_archive(tmp_path: Path) -> None:
    library = tmp_path / "botan-output" / "lib" / "libbotan-3.a"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"synthetic static archive")

    assert botan_build.find_static_library(library.parents[1]) == library



#### Resolve Android API 28's exact arm64 compiler below the caller-supplied NDK.
####
def test_android_toolchain_resolves_pinned_api_compiler(tmp_path: Path) -> None:
    ndk_root = tmp_path / "android-ndk"
    compiler = (
        ndk_root
        / "toolchains"
        / "llvm"
        / "prebuilt"
        / "linux-x86_64"
        / "bin"
        / "aarch64-linux-android28-clang++"
    )
    compiler.parent.mkdir(parents=True)
    compiler.write_bytes(b"synthetic compiler")

    options = botan_build.resolve_target_toolchain(
        "android-arm64",
        environment={"ANDROID_NDK_ROOT": str(ndk_root)},
        system="Linux",
    )

    assert options == (f"--cc-bin={compiler.resolve()}",)



#### Fail a missing Android toolchain before attempting source acquisition.
####
def test_android_toolchain_failure_precedes_source_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANDROID_NDK_ROOT", raising=False)
    monkeypatch.setattr(
        botan_build,
        "load_source_pin",
        lambda _path: pytest.fail("source pin must not be read"),
    )

    with pytest.raises(BotanBuildError, match="Android NDK toolchain is unavailable"):
        build_botan("android-arm64", tmp_path / "output", tmp_path / "cache")



#### Resolve iPhoneOS clang and its SDK through fixed xcrun commands.
####
def test_ios_toolchain_resolves_clang_and_sdk(tmp_path: Path) -> None:
    compiler = tmp_path / "Xcode" / "clang++"
    sdk = tmp_path / "Xcode" / "iPhoneOS.sdk"
    compiler.parent.mkdir(parents=True)
    compiler.write_bytes(b"synthetic compiler")
    sdk.mkdir()
    commands: list[tuple[str, ...]] = []



    #### Record xcrun discovery commands and return synthetic tool paths.
    ####
    def run_xcrun(
        command: tuple[str, ...],
        **_arguments: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        output = str(compiler) if command[-1] == "clang++" else str(sdk)
        return subprocess.CompletedProcess(command, 0, stdout=f"{output}\n", stderr="")

    options = botan_build.resolve_target_toolchain(
        "ios-arm64",
        environment={},
        system="Darwin",
        runner=run_xcrun,
    )

    assert commands == [
        ("xcrun", "--sdk", "iphoneos", "--find", "clang++"),
        ("xcrun", "--sdk", "iphoneos", "--show-sdk-path"),
    ]
    assert options == (
        f"--cc-bin={compiler.resolve()}",
        f"--cc-abi-flags={shlex.join(('-isysroot', str(sdk.resolve()), '-arch', 'arm64'))}",
    )



#### Reject iOS cross-build requests on a non-macOS host before running xcrun.
####
def test_ios_toolchain_rejects_non_macos_host() -> None:



    #### Fail if the rejected request attempts to invoke xcrun.
    ####
    def reject_run(*_arguments: object, **_keywords: object) -> subprocess.CompletedProcess[str]:
        pytest.fail("xcrun must not run outside macOS")

    with pytest.raises(BotanBuildError, match="iOS toolchain requires macOS"):
        botan_build.resolve_target_toolchain(
            "ios-arm64",
            environment={},
            system="Linux",
            runner=reject_run,
        )



#### Include only the already resolved target-specific compiler options in configuration.
####
def test_configure_command_appends_resolved_toolchain_options() -> None:
    options = (
        "--cc-bin=/synthetic/clang++",
        "--cc-abi-flags=-isysroot /synthetic/iPhoneOS.sdk -arch arm64",
    )

    command = configure_command(
        "ios-arm64",
        Path("/synthetic/botan-source"),
        Path("/synthetic/botan-output"),
        toolchain_options=options,
    )

    assert command[-2:] == options



#### Map only the host architectures represented by the approved native profiles.
####
@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    (
        ("Windows", "AMD64", "windows-x86_64"),
        ("Darwin", "arm64", "macos-arm64"),
        ("Linux", "x86_64", "linux-x86_64"),
    ),
)
def test_host_target_requires_approved_architecture(
    system: str,
    machine: str,
    expected: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setattr(platform, "machine", lambda: machine)

    assert botan_build.host_target() == expected



#### Reject an Intel macOS runner rather than silently producing the wrong host ABI.
####
def test_host_target_rejects_unapproved_architecture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")

    with pytest.raises(BotanBuildError, match="unsupported Botan host architecture"):
        botan_build.host_target()



#### Compile and link a generated C probe against the exact mobile Botan library.
####
def test_mobile_smoke_link_uses_twofish_ffi_and_resolved_toolchain(tmp_path: Path) -> None:
    output_directory = tmp_path / "botan-output"
    include_directory = output_directory / "include" / "botan-3" / "botan"
    include_directory.mkdir(parents=True)
    (include_directory / "ffi.h").write_text("synthetic header", encoding="utf-8")
    library = output_directory / "lib" / "libbotan-3.a"
    library.parent.mkdir()
    library.write_bytes(b"synthetic library")
    compiler = tmp_path / "ndk" / "aarch64-linux-android28-clang++"
    compiler.parent.mkdir()
    compiler.write_bytes(b"synthetic compiler")
    commands: list[tuple[str, ...]] = []



    #### Record the Android compiler invocation and synthesize its output.
    ####
    def run_compiler(
        command: tuple[str, ...],
        **_arguments: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        linked_output = Path(command[command.index("-o") + 1])
        linked_output.write_bytes(b"synthetic linked probe")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    linked_probe = botan_build.link_mobile_smoke_program(
        "android-arm64",
        output_directory,
        library,
        (f"--cc-bin={compiler.resolve()}",),
        runner=run_compiler,
    )

    source = (output_directory / "smoke" / "botan-ffi-smoke.c").read_text(encoding="utf-8")
    command = commands[0]
    assert linked_probe == output_directory / "smoke" / "botan-ffi-smoke"
    assert linked_probe.is_file()
    assert command[0] == str(compiler.resolve())
    source_index = command.index(str(output_directory / "smoke" / "botan-ffi-smoke.c"))
    library_index = command.index(str(library))
    assert command[source_index - 2:source_index] == ("-x", "c")
    assert command[library_index - 2:library_index] == ("-x", "none")
    assert f"-I{output_directory / 'include' / 'botan-3'}" in command
    assert str(library) in command
    assert "botan_block_cipher_init" in source
    assert "botan_block_cipher_set_key" in source
    assert "botan_block_cipher_encrypt_blocks" in source
    assert "botan_block_cipher_destroy" in source



#### Preserve iPhoneOS sysroot and architecture flags in the final link command.
####
def test_ios_smoke_link_keeps_resolved_abi_flags(tmp_path: Path) -> None:
    output_directory = tmp_path / "botan-output"
    (output_directory / "include" / "botan-3" / "botan").mkdir(parents=True)
    library = output_directory / "lib" / "libbotan-3.a"
    library.parent.mkdir()
    library.write_bytes(b"synthetic library")
    compiler = tmp_path / "Xcode" / "clang++"
    compiler.parent.mkdir()
    compiler.write_bytes(b"synthetic compiler")
    sdk = tmp_path / "Xcode" / "iPhoneOS.sdk"
    sdk.mkdir()
    commands: list[tuple[str, ...]] = []



    #### Record the iOS compiler invocation and synthesize its output.
    ####
    def run_compiler(
        command: tuple[str, ...],
        **_arguments: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        Path(command[command.index("-o") + 1]).write_bytes(b"linked")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    botan_build.link_mobile_smoke_program(
        "ios-arm64",
        output_directory,
        library,
        (
            f"--cc-bin={compiler.resolve()}",
            f"--cc-abi-flags={shlex.join(('-isysroot', str(sdk.resolve()), '-arch', 'arm64'))}",
        ),
        runner=run_compiler,
    )

    assert commands[0][1:5] == ("-isysroot", str(sdk.resolve()), "-arch", "arm64")



#### Reject a smoke-link request for a host profile before writing a probe.
####
def test_mobile_smoke_link_rejects_host_target(tmp_path: Path) -> None:
    with pytest.raises(BotanBuildError, match="mobile smoke target is unsupported"):
        botan_build.link_mobile_smoke_program(
            "linux-x86_64",
            tmp_path / "output",
            tmp_path / "libbotan-3.so",
            (),
        )



#### Forward the explicit smoke-link request only through the mobile build invocation.
####
def test_main_forwards_mobile_smoke_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    library = (tmp_path / "output" / "lib" / "libbotan-3.a").resolve()
    library.parent.mkdir(parents=True)
    library.write_bytes(b"synthetic library")
    calls: list[tuple[str, bool]] = []



    #### Record CLI build forwarding and return the synthetic library.
    ####
    def fake_build(
        target: str,
        _output: Path,
        _cache: Path,
        *,
        smoke_link: bool = False,
    ) -> Path:
        calls.append((target, smoke_link))
        return library

    monkeypatch.setattr(botan_build, "build_botan", fake_build)

    result = main(
        [
            "--target",
            "android-arm64",
            "--output",
            str(tmp_path / "output"),
            "--smoke-link",
        ]
    )

    assert result == 0
    assert calls == [("android-arm64", True)]
    assert capsys.readouterr().out == f"{library} Botan 3.13.0\n"



#### Keep both mobile compile/link jobs and their platform toolchain handoffs in hosted CI.
####
def test_workflow_contains_android_and_ios_smoke_jobs() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "foundation.yml").read_text(encoding="utf-8")

    assert "android-cross:" in workflow
    assert "$env:ANDROID_NDK_ROOT = $env:ANDROID_NDK_LATEST_HOME" in workflow
    assert "--target android-arm64 --output build/botan-android --smoke-link" in workflow
    assert "ios-cross:" in workflow
    assert "--target ios-arm64 --output build/botan-ios --smoke-link" in workflow
