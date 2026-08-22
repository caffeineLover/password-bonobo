# Password Bonobo

Password Bonobo is an original, local-file-first password manager built around a fully typed Python core.

The project is in foundation and compatibility-research development.  It does not yet provide a usable vault.

## Design

The approved program design is in `docs/specs/password-bonobo-python-reimplementation-design.md`.

## Source boundary

Password Gorilla is studied only through an external, pinned, read-only research checkout.  Gorilla source and other
copyrightable implementation material do not enter this repository or Bonobo product builds.

## Security

Never add real credentials, personal PasswordSafe databases, tokens, or sensitive provider metadata.  Report security
issues through the [security policy](SECURITY.md).

## License

Bonobo-authored code is licensed under [GPL-3.0-or-later](LICENSES/GPL-3.0-or-later.txt).  Machine-readable metadata
is in [`REUSE.toml`](REUSE.toml).  External contributions remain closed while the iOS distribution-exception decision
is unresolved; see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[App Store distribution exception plan](docs/legal/app-store-distribution-exception-plan.md).
