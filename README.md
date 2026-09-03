# Ipê package registry

The curated index of publishable [Ipê](https://github.com/arthurmaciel/ipe-lang)
packages. It is a plain git repository: one file per package at
`packages/<name>.toml`, each pinning every published version to an exact source
revision, a content hash, and a declared capability set.

`ipe add <name>` resolves a dependency through this index — it reads the entry,
picks the highest version matching your request, `git fetch`es the source at the
pinned revision, verifies the tree's `sha256` against the pin, writes the
lockfile, and records the dependency in `ipe.toml`. Once locked, a build is
reproducible from the lockfile alone; the index need not be reachable.

## Entry schema — `packages/<name>.toml`

```toml
name = "http-extras"          # must match the file stem
publisher = "arthurmaciel"    # the GitHub account vouching for this entry

[[versions]]
version = "1.2.0"                                       # semver
source = "https://github.com/arthurmaciel/http-extras" # git remote
rev = "9f2c1a7e0b…"                                     # exact commit (pinned)
sha256 = "3b1f…"                                        # hash of the fetched tree
capabilities = ["network"]                             # declared capability set
```

`capabilities` is the set the package's code exercises (inferred for pure Ipê,
declared for native `Rust.` code). `ipe add` surfaces it for consent at install —
loudly when it includes `native-ffi`.

## Submitting a package

Open a pull request that adds or updates `packages/<name>.toml`. The **admission
gate** (`.github/workflows/admission.yml`) runs before merge: it audits the
proposed entry (capability declared-vs-inferred, enforced semver, supply chain,
provenance) and, for native packages, builds and probes the source inside an
off-the-shelf sandbox on every platform Ipê ships a binary for. An entry merges
only when the gate is green on every platform. A red gate, or a sandbox that
cannot establish on any platform, rejects — never a warning.

The trust model — admission is the boundary we enforce; execution is the user's
consented choice — is recorded in the language repo's ADRs 0040 and 0041.

## Consuming the index

```
ipe add http-extras            # resolve latest matching, lock, record in ipe.toml
ipe add http-extras@^1.2       # a version request
```

See `CONTRIBUTING.md` for the full submission flow.

## Static read API

The curated TOML is the source of truth; the resolver reads a JSON mirror of it,
published to GitHub Pages by `.github/workflows/pages.yml` on every push to main
(`.github/scripts/generate_site.py` renders `packages/` and `advisories/` into
`_site/`). The read paths a client fetches:

| Path | Content |
| --- | --- |
| `index.json` | Discovery catalogue: `{ packages: [ { name, publisher, latest } ] }`. |
| `packages/<name>.json` | One entry: `{ publisher, versions: [ { version, source, rev, sha256, capabilities } ] }` — a faithful mirror of `packages/<name>.toml`. |
| `advisories/index.json` | `{ advisories: [ { id, package } ] }` (empty until advisories land). |
| `advisories/<id>.json` | One advisory record. |

The resolver's default base is overridable with `IPE_REGISTRY_URL`. The generator
translates format only — it never invents or drops a field; where its JSON and
the resolver parser (`src/ipe-cli/src/{index,advisory}.rs`) disagree, the parser
governs and the mismatch is a generator bug.
