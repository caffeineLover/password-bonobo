"""Verify exact document coverage, commands, and non-mutating TeX verification."""

import shutil
import subprocess
from pathlib import Path

import pytest
from tools.generate_documents import (
    MAXIMUM_XELATEX_PASSES,
    XELATEX_PASSES,
    build_pandoc_command,
    build_xelatex_command,
    check_document_coverage,
    discover_document_specs,
    latex_requires_rerun,
    main,
    prepare_output_directory,
    verify_generated_tex,
)



#### Require callers to name every document before any LaTeX or PDF work begins.
####
def test_document_cli_requires_explicit_document_selection(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as captured:
        main(("--verify", "--repository-root", str(tmp_path)))

    assert captured.value.code == 2



#### Restrict discovery and pair enforcement to the explicitly selected Markdown source.
####
def test_document_manifest_discovers_only_explicit_selection(tmp_path: Path) -> None:
    (tmp_path / "docs" / "nested").mkdir(parents=True)
    selected = tmp_path / "docs" / "selected.md"
    selected.write_text("# Selected\n", encoding="utf-8")
    selected.with_suffix(".tex").write_text("generated\n", encoding="utf-8")
    unselected = tmp_path / "docs" / "nested" / "unselected.md"
    unselected.write_text("# Unselected\n", encoding="utf-8")

    specs = discover_document_specs(tmp_path, (Path("docs/selected.md"),))

    assert check_document_coverage(tmp_path, (Path("docs/selected.md"),)) == ()
    assert tuple(spec.markdown_relative_path.as_posix() for spec in specs) == ("docs/selected.md",)



#### Discover every nested Markdown and LaTeX pair in stable relative-path order.
####
def test_document_manifest_discovers_every_pair(tmp_path: Path) -> None:
    (tmp_path / "docs" / "nested").mkdir(parents=True)
    for relative_path in (Path("docs/alpha.md"), Path("docs/nested/beta.md")):
        markdown_path = tmp_path / relative_path
        markdown_path.write_text(f"# {relative_path.stem}\n", encoding="utf-8")
        markdown_path.with_suffix(".tex").write_text("generated\n", encoding="utf-8")

    specs = discover_document_specs(tmp_path)

    assert tuple(spec.markdown_relative_path.as_posix() for spec in specs) == (
        "docs/alpha.md",
        "docs/nested/beta.md",
    )
    assert check_document_coverage(tmp_path) == ()



#### Keep the live project-memory checkpoint as Markdown-only agent state rather than a generated review document.
####
def test_document_manifest_excludes_markdown_only_project_memory(tmp_path: Path) -> None:
    docs_root = tmp_path / "docs"
    docs_root.mkdir()
    (docs_root / "PROJECT_MEMORY.md").write_text("# Project Memory\n", encoding="utf-8")
    guide_path = docs_root / "guide.md"
    guide_path.write_text("# Guide\n", encoding="utf-8")
    guide_path.with_suffix(".tex").write_text("generated\n", encoding="utf-8")

    specs = discover_document_specs(tmp_path)

    assert check_document_coverage(tmp_path) == ()
    assert tuple(spec.markdown_relative_path.as_posix() for spec in specs) == ("docs/guide.md",)



#### Honor Git's document boundary while retaining non-ignored untracked authoring input.
####
def test_document_manifest_honors_git_document_boundary(tmp_path: Path) -> None:
    subprocess.run(("git", "init", "--quiet", str(tmp_path)), check=True)
    docs_root = tmp_path / "docs"
    prompt_root = docs_root / "prompts"
    prompt_root.mkdir(parents=True)
    (tmp_path / ".gitignore").write_text("/docs/prompts/\n", encoding="utf-8")
    tracked_markdown = docs_root / "owned.md"
    tracked_markdown.write_text("# Owned\n", encoding="utf-8")
    tracked_markdown.with_suffix(".tex").write_text("generated\n", encoding="utf-8")
    (prompt_root / "local-standard.md").write_text("# Ignored local standard\n", encoding="utf-8")
    ignored_markdown_peer = prompt_root / "tracked-tex.md"
    ignored_markdown_peer.write_text("# Ignored Markdown peer\n", encoding="utf-8")
    tracked_tex = ignored_markdown_peer.with_suffix(".tex")
    tracked_tex.write_text("tracked TeX\n", encoding="utf-8")
    (docs_root / "draft.md").write_text("# Untracked draft\n", encoding="utf-8")
    subprocess.run(
        (
            "git",
            "-C",
            str(tmp_path),
            "add",
            ".gitignore",
            "docs/owned.md",
            "docs/owned.tex",
        ),
        check=True,
    )
    subprocess.run(
        ("git", "-C", str(tmp_path), "add", "--force", "docs/prompts/tracked-tex.tex"),
        check=True,
    )

    violations = check_document_coverage(tmp_path)
    specs = discover_document_specs(tmp_path)

    assert tuple((violation.path.as_posix(), violation.message) for violation in violations) == (
        ("docs/draft.md", "Markdown document has no same-basename repository-owned LaTeX source"),
        ("docs/prompts/tracked-tex.tex", "LaTeX document has no same-basename repository-owned Markdown source"),
    )
    assert tuple(spec.markdown_relative_path.as_posix() for spec in specs) == (
        "docs/draft.md",
        "docs/owned.md",
    )



#### Ignore cached paths whose paired document sources were deleted from the working tree but are not yet staged.
####
def test_document_manifest_ignores_unstaged_paired_deletions(tmp_path: Path) -> None:
    subprocess.run(("git", "init", "--quiet", str(tmp_path)), check=True)
    docs_root = tmp_path / "docs"
    docs_root.mkdir()
    markdown_path = docs_root / "retired.md"
    tex_path = markdown_path.with_suffix(".tex")
    markdown_path.write_text("# Retired\n", encoding="utf-8")
    tex_path.write_text("generated\n", encoding="utf-8")
    subprocess.run(
        ("git", "-C", str(tmp_path), "add", "docs/retired.md", "docs/retired.tex"),
        check=True,
    )
    markdown_path.unlink()
    tex_path.unlink()

    assert check_document_coverage(tmp_path) == ()
    assert discover_document_specs(tmp_path) == ()



#### Fail closed when a repository has a Git directory but the Git executable is unavailable.
####
def test_document_manifest_requires_git_for_repository_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess.run(("git", "init", "--quiet", str(tmp_path)), check=True)
    monkeypatch.setenv("PATH", "")

    with pytest.raises(RuntimeError) as captured:
        check_document_coverage(tmp_path)

    message = str(captured.value)
    assert "Git executable is unavailable" in message
    assert str(tmp_path) in message
    assert "filesystem fallback is disabled" in message



#### Fail closed when exact-root discovery fails for a linked worktree with Git-file metadata.
####
def test_document_manifest_rejects_failed_exact_root_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = tmp_path / "repository"
    linked_root = tmp_path / "linked-root"
    subprocess.run(("git", "init", "--quiet", str(repository_root)), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(repository_root),
            "-c",
            "user.name=Document Test",
            "-c",
            "user.email=document-test@example.invalid",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "baseline",
        ),
        check=True,
    )
    subprocess.run(
        ("git", "-C", str(repository_root), "worktree", "add", "--quiet", "--detach", str(linked_root), "HEAD"),
        check=True,
    )
    assert (linked_root / ".git").is_file()
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "missing-git-directory"))

    with pytest.raises(RuntimeError) as captured:
        discover_document_specs(linked_root)

    message = str(captured.value)
    assert "Git could not confirm the exact repository root" in message
    assert str(linked_root) in message
    assert "filesystem fallback is disabled" in message



#### Report each unpaired Markdown or LaTeX document instead of silently omitting it.
####
def test_document_manifest_rejects_unpaired_sources(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "missing-tex.md").write_text("# Missing TeX\n", encoding="utf-8")
    (tmp_path / "docs" / "missing-markdown.tex").write_text("generated\n", encoding="utf-8")

    messages = frozenset(violation.message for violation in check_document_coverage(tmp_path))

    assert messages == frozenset({
        "Markdown document has no same-basename repository-owned LaTeX source",
        "LaTeX document has no same-basename repository-owned Markdown source",
    })



#### Keep an unpaired Markdown source discoverable so write mode can create its first generated TeX file.
####
def test_document_manifest_discovers_markdown_before_generated_tex_exists(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    markdown_path = tmp_path / "docs" / "new-document.md"
    markdown_path.write_text("# New Document\n", encoding="utf-8")

    specs = discover_document_specs(tmp_path)

    assert tuple(spec.tex_relative_path.as_posix() for spec in specs) == ("docs/new-document.tex",)



#### Build the exact repository Pandoc and two-pass XeLaTeX command contract.
####
def test_document_commands_use_repository_layout_inputs_and_two_xelatex_passes(tmp_path: Path) -> None:
    (tmp_path / "docs" / "pandoc").mkdir(parents=True)
    markdown_path = tmp_path / "docs" / "guide.md"
    tex_path = markdown_path.with_suffix(".tex")
    markdown_path.write_text("# Exact Guide\n", encoding="utf-8")
    tex_path.write_text("generated\n", encoding="utf-8")
    spec = discover_document_specs(tmp_path)[0]
    candidate_path = tmp_path / "tmp" / "generated" / "guide.tex"
    build_directory = tmp_path / "tmp" / "build" / "guide"

    pandoc_command = build_pandoc_command(spec, tmp_path, candidate_path)
    xelatex_command = build_xelatex_command(spec, tmp_path, build_directory)

    assert pandoc_command == (
        "pandoc",
        str(markdown_path),
        "--from=gfm",
        "--to=latex",
        "--standalone",
        "--toc",
        "--listings",
        "--wrap=auto",
        "--columns=120",
        f"--include-in-header={tmp_path / 'docs' / 'pandoc' / 'pdf-header.tex'}",
        f"--lua-filter={tmp_path / 'docs' / 'pandoc' / 'pdf-layout.lua'}",
        "--metadata=title=Exact Guide",
        "--variable=papersize:letter",
        "--variable=geometry:margin=0.8in",
        f"--output={candidate_path}",
    )
    assert xelatex_command == (
        "xelatex",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-file-line-error",
        f"-output-directory={build_directory}",
        str(tex_path),
    )
    assert XELATEX_PASSES == 2
    assert MAXIMUM_XELATEX_PASSES == 3



#### Detect compiler requests for one bounded stabilization pass without confusing package names for warnings.
####
def test_xelatex_rerun_detection_is_warning_specific() -> None:
    assert latex_requires_rerun("LaTeX Warning: Label(s) may have changed. Rerun to get cross-references right.")
    assert not latex_requires_rerun("Package: rerunfilecheck 2025-06-21 v1.11")



#### Compare normalized generated TeX without modifying the tracked source.
####
def test_tex_verification_is_exact_and_non_mutating(tmp_path: Path) -> None:
    tracked_path = tmp_path / "guide.tex"
    candidate_path = tmp_path / "candidate.tex"
    tracked_path.write_bytes(b"first\r\nsecond\r\n")
    candidate_path.write_bytes(b"first\nsecond\n")
    before = tracked_path.read_bytes()

    assert verify_generated_tex(tracked_path, candidate_path) == ()
    candidate_path.write_text("first\nchanged\n", encoding="utf-8")
    messages = tuple(violation.message for violation in verify_generated_tex(tracked_path, candidate_path))

    assert messages == ("generated LaTeX differs from the tracked source",)
    assert tracked_path.read_bytes() == before



#### Remove stale compiler state before a new deterministic two-pass document build.
####
def test_output_directory_preparation_removes_stale_auxiliary_files(tmp_path: Path) -> None:
    output_directory = tmp_path / "build" / "guide"
    output_directory.mkdir(parents=True)
    stale_auxiliary = output_directory / "guide.aux"
    stale_auxiliary.write_text("stale labels\n", encoding="utf-8")

    prepare_output_directory(output_directory)

    assert output_directory.is_dir()
    assert tuple(output_directory.iterdir()) == ()



#### Keep a wide table's heading and introduction inside the same landscape block.
####
@pytest.mark.skipif(shutil.which("pandoc") is None, reason="Pandoc is required for the layout integration check")
def test_wide_table_layout_keeps_section_context_in_landscape(tmp_path: Path) -> None:
    markdown_path = tmp_path / "layout.md"
    output_path = tmp_path / "layout.tex"
    markdown_path.write_text(
        """# Layout fixture

## Fabricated assets

This introduction belongs with the wide table.

| One | Two | Three | Four | Five | Six | Seven | Eight |
|---|---|---|---|---|---|---|---|
| a | b | c | d | e | f | g | h |

## Following section
""",
        encoding="utf-8",
    )

    subprocess.run(
        (
            "pandoc",
            str(markdown_path),
            "--from=gfm",
            "--to=latex",
            f"--lua-filter={Path.cwd() / 'docs' / 'pandoc' / 'pdf-layout.lua'}",
            f"--output={output_path}",
        ),
        check=True,
    )
    generated = output_path.read_text(encoding="utf-8")

    assert generated.index("\\begin{landscape}") < generated.index("\\subsection{Fabricated assets}")
    assert generated.index("\\subsection{Fabricated assets}") < generated.index("This introduction belongs")
    assert generated.index("This introduction belongs") < generated.index("\\begin{longtable}")
    assert generated.index("\\end{longtable}") < generated.index("\\end{landscape}")
    assert generated.index("\\end{landscape}") < generated.index("\\subsection{Following section}")



#### Keep Gorilla compatibility authorities Markdown-only unless the user later names one for generation.
####
def test_repository_gorilla_documents_have_no_latex_or_pdf_derivatives() -> None:
    gorilla_root = Path.cwd() / "docs" / "compatibility" / "gorilla"

    assert tuple(gorilla_root.glob("*.tex")) == ()
    assert tuple(gorilla_root.glob("*.pdf")) == ()
