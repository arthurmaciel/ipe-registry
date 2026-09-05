# Contributing a package

1. **Fork** this repository (or branch, if you have write access).
2. **Add or edit** `packages/<name>.toml` for your package. For a new version,
   append a `[[version]]` block; never edit or delete a published version (they
   are immutable — a build may be locked to one).
   - `rev` must be an exact, immutable git commit (not a branch or tag ref).
   - `sha256` is the hash `ipe` computes over the fetched source tree. `ipe
     package audit` prints the value to record.
   - `capabilities` must be exactly the set the code exercises — no more (an
     over-broad declaration is rejected), no less (a hidden effect is rejected).
3. **Open a pull request.** The admission gate runs automatically.
4. **Green merges, red does not.** The gate is authoritative; the same audit you
   can run locally with `ipe package audit` runs here across every shipped
   platform.

## Rules

- One package per `packages/<name>.toml`; the file stem is the canonical name.
- Published versions are append-only and immutable.
- `source` must be a public git remote reachable by `git fetch`.
- Semver is enforced against the previously published version (an under-bump —
  a breaking change without the matching version bump — is rejected).
