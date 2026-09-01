# Project Agent Instructions

Instructions version: 0.3.0

Before working on this project, read and follow the shared standards router at
`E:\home\Code\Code Agent Prompts\docs\prompts\AGENTS.md`.

Treat everything under `E:\home\Code\Code Agent Prompts\docs\prompts\` as read-only.  Do not modify, rename, move,
delete, reformat, or version the shared standards files.  Project-specific instructions and approved exceptions belong
in this file or the repository's enforced configuration.

## Project-Specific Instructions

Use `docs/PROJECT_MEMORY.md` as this repository's sole persistent continuation and handoff record.  Read it completely
before resumed or substantial work, follow its linked-record read order, and reconcile it against the repository and
Git state before relying on it.

Update `docs/PROJECT_MEMORY.md` throughout active work at every meaningful checkpoint and before any interruption.  It
must state the current task, the last verified result, work in progress, the exact immediate next actions in order, and
the approved work after those actions so another session can resume without conversation history.

Do not create `HANDOFF.md`, `HANDOFF.tex`, or `HANDOFF.pdf`.  `docs/PROJECT_MEMORY.md` is an approved Markdown-only
exception to the shared generated-document policy: do not create or retain same-basename LaTeX or PDF versions.  Keep
the memory concise, accurate, nonsensitive, and subordinate to the current code, configuration, tests, and Git state.

Do not place project-specific changes in the shared standards repository.
