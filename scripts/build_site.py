#!/usr/bin/env python3
# Mirror the registry TOML tree to the static JSON read API the ipe CLI fetches:
#   site/packages/<name>.json    (1:1 from packages/<name>.toml)
#   site/advisories/<id>.json     (1:1 from advisories/<id>.toml)
#   site/advisories/index.json    (catalogue: id -> affected package, for the CLI's
#                                   advisory lookup by package name)
# The package entry JSON is parsed by the CLI through the same typed constructors as
# the TOML path (parse, don't validate), so field names must match the entry schema:
#   name, publisher, versions[] { version, source, rev, sha256, capabilities, signature? }
import json
import pathlib
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

root = pathlib.Path(".")
site = root / "site"
(site / "packages").mkdir(parents=True, exist_ok=True)
(site / "advisories").mkdir(parents=True, exist_ok=True)


def load(p):
    with open(p, "rb") as f:
        return tomllib.load(f)


pkgs = 0
for p in sorted((root / "packages").glob("*.toml")):
    raw = load(p)
    # The CLI's JSON read-path (parse_entry_json) reads: publisher (string) and
    # versions (ARRAY, plural) of { version, source, rev, sha256, capabilities }.
    # The TOML uses `[[version]]` (singular array-of-tables) -> remap to `versions`.
    # The authoritative package name is the file stem.
    entry = {
        "name": raw.get("name", p.stem),
        "publisher": raw.get("publisher"),
        "versions": raw.get("versions", raw.get("version", [])),
    }
    (site / "packages" / (p.stem + ".json")).write_text(
        json.dumps(entry, indent=2, default=str)
    )
    pkgs += 1

index = []
for p in sorted((root / "advisories").glob("*.toml")):
    data = load(p)
    (site / "advisories" / (p.stem + ".json")).write_text(
        json.dumps(data, indent=2, default=str)
    )
    index.append({"id": data.get("id", p.stem),
                  "affected": data.get("affected", data.get("package", ""))})

(site / "advisories" / "index.json").write_text(json.dumps(index, indent=2))
(site / "index.json").write_text(json.dumps(
    {"registry": "ipe-registry",
     "endpoints": ["/packages/<name>.json", "/advisories/index.json", "/advisories/<id>.json"]},
    indent=2))
print(f"built {pkgs} package JSON, {len(index)} advisory JSON")
