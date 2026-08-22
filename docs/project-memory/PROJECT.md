# Password Bonobo Project Identity

Last updated: 2026-08-22

## Overview and current state

Password Bonobo is an original, local-file-first password manager intended to preserve meaningful Password Gorilla
compatibility through a fully typed Python core and platform-appropriate clients.  The repository currently contains
foundation infrastructure and a neutral compatibility contract, not vault product behavior.

## Product contract

- Supported targets are Windows, macOS, Linux, Android, ChromeOS through Android, and iOS.  BSD portability remains a
  core goal whose official support depends on packaging, CI, and real-system qualification.
- Vault storage is local-file-first.  User-selected operating-system document providers may synchronize files, but
  Bonobo will not operate an account system, cloud vault, or synchronization service.
- Loss of credentials or user-authored metadata is unacceptable.  PasswordSafe files are lossless documents, including
  stable identifiers, supported standard fields, and preservable unknown field bytes.
- Bonobo-authored material is licensed under GPL-3.0-or-later.  The possible iOS distribution exception remains an
  unresolved, separately reviewed decision and creates no current permission.

## Authoritative documents

- [Program design](../specs/password-bonobo-python-reimplementation-design.md)
- [Repository-foundation specification](../specs/password-bonobo-repository-foundation-compatibility-dossier-spec.md)
- [URL-audit design](../specs/password-bonobo-url-audit-design.md)
- [Source-provenance policy](../legal/source-provenance-policy.md)
- [Compatibility matrix](../compatibility/gorilla/feature-parity-matrix.md)
- [Black-box test oracles](../compatibility/gorilla/test-oracles.md)
