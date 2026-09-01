# Project Agent Instructions

Instructions version: 0.8.0

Before working on this project, read and follow the shared standards router at
`E:\home\Code\Code Agent Prompts\docs\prompts\AGENTS.md`.

Treat everything under `E:\home\Code\Code Agent Prompts\docs\prompts\` as read-only.  Do not modify, rename, move,
delete, reformat, or version the shared standards files.  Project-specific instructions and approved exceptions belong
in this file or the repository's enforced configuration.

## Project-Specific Instructions

Use `docs/PROJECT_MEMORY.md` as this repository's sole persistent continuation and handoff record.  Read it completely
before resumed or substantial work, and reconcile it against the repository and Git state before relying on it.  Do
not create a second project-memory file or folder.

Update `docs/PROJECT_MEMORY.md` throughout active work at every meaningful checkpoint and before any interruption.  It
must state the current task, the last verified result, work in progress, the exact immediate next actions in order, and
the approved work after those actions so another session can resume without conversation history.

Do not create `HANDOFF.md`, `HANDOFF.tex`, or `HANDOFF.pdf`.  `docs/PROJECT_MEMORY.md` is an approved Markdown-only
exception to the shared generated-document policy: do not create or retain same-basename LaTeX or PDF versions.  Keep
the memory concise, accurate, nonsensitive, and subordinate to the current code, configuration, tests, and Git state.

Treat Markdown as the default and canonical document format.  Do not generate, regenerate, verify, or retain LaTeX or
PDF derivatives unless the user explicitly names each document that should have them.  Preserve existing LaTeX outside
named Markdown-only directories until the user directs otherwise.  Everything under `docs/compatibility/gorilla/` is
Markdown-only: do not create or retain `.tex` or `.pdf` files there.  The document tool requires one repeated
`--document` selection per approved Markdown source and must never be invoked as a repository-wide operation.

Everything under `docs/legal/` is also Markdown-only until the user explicitly reverses this restriction.  Do not
create or retain `.tex` or `.pdf` files there, and do not pass a legal Markdown source to the document generator.

Everything under `docs/specs/` is likewise Markdown-only until the user explicitly reverses this restriction.  Do not
create or retain `.tex` or `.pdf` files there, and do not pass a specification Markdown source to the generator.

Everything under `docs/superpowers/plans/` is Markdown-only until explicitly reversed.  Do not create or retain `.tex`
or `.pdf` files there, and do not pass an implementation-plan Markdown source to the generator.

Everything under `docs/superpowers/specs/` is Markdown-only until explicitly reversed.  Do not create or retain `.tex`
or `.pdf` files there, and do not pass an approved-design Markdown source to the generator.

Do not place project-specific changes in the shared standards repository.
