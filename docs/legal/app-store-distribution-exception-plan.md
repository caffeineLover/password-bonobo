# App Store Distribution Exception Plan

## Purpose

Apple platform distribution terms may create a distribution problem for a GPL-licensed application.  This document
plans the review needed to decide whether a narrowly scoped distribution exception is appropriate for Password Bonobo.
It does not decide that question and does not publish exception language.

## Proposed scope constraints

Any future exception would be limited to Bonobo-authored code for which every relevant contributor granted the necessary
permission.  It would not apply to Gorilla-derived code, which is excluded from Bonobo product builds, or to
dependencies whose licenses or terms are incompatible with the approved iOS distribution model.

No contributor permission, license exception, or iOS distribution right is created by this planning document.

## Required reviews

Before any decision, the project must complete and record these reviews:

- A dependency review covering licenses, distribution terms, and iOS build inclusion.
- A contributor-rights review covering the permission needed for the final approved scope.
- An Apple-term review using the terms applicable at the time of the decision.
- A legal review of the distribution model, proposed scope, and final wording.

## Decision gates

External contributions remain closed until the contribution terms can preserve GPL-3.0-or-later licensing and any
approved distribution exception rights for Bonobo-authored iOS code.  The repository owner must deliberately publish
the contribution terms before accepting external contributions.

Before the first iOS distribution build, the project must confirm the final exception decision, contributor permissions,
dependency compatibility, Apple-term review, and legal review.  The iOS build must exclude Gorilla-derived code and any
incompatible dependency.

## Status and limitations

This is a planning document, not license text or legal advice.  It must not be cited as final exception language,
contributor permission, or approval to distribute an iOS build.
