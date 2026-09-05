# Security advisories

A security advisory warns consumers that a range of a package's published
versions is vulnerable. `ipe add` consults advisories and **fails closed** on a
high/critical match in range, warns on low/medium, and treats a present-but-
malformed advisory database as a hard error — never as "no advisories".

## Source of truth — `advisories/<package>/<id>.toml`

One file per advisory, nested under a per-package directory (the directory name
is the package it concerns). One advisory concerns exactly one package; an
incident spanning N packages is N advisory files with N distinct ids.

```toml
id          = "IPE-2026-0001"        # must equal the file stem; charset [A-Za-z0-9._-], no leading '-'
package     = "http-client"          # must equal the parent directory name; must name an existing packages/<package>.toml
severity    = "high"                 # low | medium | high | critical (lowercase)
affected    = ">=1.0.0, <1.2.3"      # a semver VersionReq
description  = "SSRF via unvalidated redirect target."   # short; printed verbatim at `ipe add`
fixed_in    = "1.2.3"                # optional semver; OMIT the key when no fix exists
```

Every field except `fixed_in` is required; a violated constraint is rejected at
admission and is a hard parse error in the CLI (the same rule enforced at both
ends of the wire).

**Immutability.** `id`, `package`, and `affected` never change once published;
`severity`, `description`, and `fixed_in` may be amended by pull request (e.g.
add `fixed_in` when a fix ships, or re-score severity). Advisory files are not
deleted.

## JSON read path (generated — do not hand-edit)

The Pages workflow (`scripts/build_site.py`) mirrors the TOML tree to the static
JSON the CLI fetches:

- `advisories/<id>.json` — a field-for-field mirror of the record above (with an
  absent/empty `fixed_in` omitted).
- `advisories/index.json` — the catalogue the CLI selects by package name:

  ```json
  { "advisories": [ { "id": "IPE-2026-0001", "package": "http-client" } ] }
  ```

  It is always a JSON **object** with an `advisories` array (a bare `[]` is
  rejected); an empty registry emits `{ "advisories": [] }`. Elements are sorted
  by `id`. The converter fails the Pages build on any malformed advisory, so a
  bad record can never reach the mirror.
