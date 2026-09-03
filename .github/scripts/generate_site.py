#!/usr/bin/env python3
"""Render the static read API + browse pages the Ipê resolver fetches.

Input  (this repository, the source of truth):
  packages/<name>.toml        one curated index entry per package (SCHEMA.md)
  advisories/<id>.toml         optional security advisories (ADVISORY-SCHEMA.md)

Output (`_site/`, deployed to GitHub Pages):
  index.json                   catalogue of every package name -> latest version
  packages/<name>.json         { publisher, versions: [ { version, source, rev,
                                 sha256, capabilities } ] }  -- the exact shape
                                 the resolver's parse_entry_json reads
  advisories/index.json        { advisories: [ { id, package } ] }
  advisories/<id>.json         one advisory record
  index.html                   a human-browsable listing

The JSON is a faithful mirror of the TOML: this generator translates format, it
never invents or drops a field. Where the emitted JSON and the resolver parser
disagree, the parser (src/ipe-cli/src/{index,advisory}.rs) governs and the
mismatch is a bug here. The file stem is the authoritative package / advisory id
(SCHEMA.md), so this generator derives names from stems, never from an in-file
key.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - local dev on older Python
    import tomli as tomllib  # type: ignore

# The closed capability vocabulary, mirrored from SCHEMA.md (which mirrors the
# compiler kernel registry). An unknown capability is a hard error here so a typo
# can never reach a client as a silently-dropped, un-consented capability.
CAPABILITIES = {
    "network",
    "filesystem",
    "database",
    "clock",
    "random",
    "environment",
    "process",
    "ffi",
}

SEVERITIES = {"low", "medium", "high", "critical"}


class SchemaError(Exception):
    """A source TOML file violates the schema; abort the whole build."""


def _require(mapping: dict, key: str, path: Path) -> object:
    if key not in mapping:
        raise SchemaError(f"{path}: missing required field `{key}`")
    return mapping[key]


def _require_str(mapping: dict, key: str, path: Path) -> str:
    value = _require(mapping, key, path)
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{path}: field `{key}` must be a non-empty string")
    return value


def parse_package(path: Path) -> tuple[str, dict]:
    """Parse one packages/<name>.toml into (name, json-ready entry)."""
    name = path.stem
    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    declared = raw.get("name")
    if declared is not None and declared != name:
        raise SchemaError(
            f"{path}: in-file name `{declared}` must equal the file stem `{name}`"
        )

    publisher = _require_str(raw, "publisher", path)

    raw_versions = raw.get("version")
    if not isinstance(raw_versions, list) or not raw_versions:
        raise SchemaError(f"{path}: at least one `[[version]]` block is required")

    versions = []
    for block in raw_versions:
        if not isinstance(block, dict):
            raise SchemaError(f"{path}: each `[[version]]` must be a table")
        caps = block.get("capabilities", [])
        if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
            raise SchemaError(f"{path}: `capabilities` must be an array of strings")
        unknown = sorted(set(caps) - CAPABILITIES)
        if unknown:
            raise SchemaError(
                f"{path}: unknown capabilities {unknown}; the vocabulary is closed"
            )
        versions.append(
            {
                "version": _require_str(block, "version", path),
                "source": _require_str(block, "source", path),
                "rev": _require_str(block, "rev", path),
                "sha256": _require_str(block, "sha256", path),
                # Sorted for a deterministic, diff-stable artifact.
                "capabilities": sorted(caps),
            }
        )

    entry = {"publisher": publisher, "versions": versions}
    return name, entry


def parse_advisory(path: Path) -> dict:
    """Parse one advisories/<id>.toml into a json-ready advisory record."""
    advisory_id = path.stem
    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    declared = raw.get("id")
    if declared is not None and declared != advisory_id:
        raise SchemaError(
            f"{path}: in-file id `{declared}` must equal the file stem `{advisory_id}`"
        )

    severity = _require_str(raw, "severity", path)
    if severity not in SEVERITIES:
        raise SchemaError(
            f"{path}: severity `{severity}` is not one of {sorted(SEVERITIES)}"
        )

    record = {
        "id": advisory_id,
        "package": _require_str(raw, "package", path),
        "severity": severity,
        # `affected` is a single semver VersionReq string, mirroring the resolver
        # (src/ipe-cli/src/advisory.rs reads it as one `semver::VersionReq`).
        "affected": _require_str(raw, "affected", path),
        "description": _require_str(raw, "description", path),
    }
    fixed_in = raw.get("fixed_in")
    if fixed_in is not None:
        if not isinstance(fixed_in, str) or not fixed_in:
            raise SchemaError(f"{path}: `fixed_in`, if present, must be a non-empty string")
        record["fixed_in"] = fixed_in
    return record


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_html(packages: dict[str, dict], advisories: list[dict]) -> str:
    rows = []
    for name in sorted(packages):
        entry = packages[name]
        latest = entry["versions"][-1]["version"]
        publisher = html.escape(entry["publisher"])
        rows.append(
            f"<tr><td><a href='packages/{html.escape(name)}.json'>"
            f"{html.escape(name)}</a></td><td>{html.escape(latest)}</td>"
            f"<td>{publisher}</td></tr>"
        )
    adv_rows = [
        f"<tr><td><a href='advisories/{html.escape(a['id'])}.json'>"
        f"{html.escape(a['id'])}</a></td><td>{html.escape(a['package'])}</td>"
        f"<td>{html.escape(a['severity'])}</td></tr>"
        for a in sorted(advisories, key=lambda a: a["id"])
    ]
    adv_section = (
        "<h2>Advisories</h2><table><tr><th>ID</th><th>Package</th><th>Severity</th></tr>"
        + "".join(adv_rows)
        + "</table>"
        if adv_rows
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Ipê package registry</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #ddd}}
code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}}
</style></head><body>
<h1>Ipê package registry</h1>
<p>A curated, git-backed index. Machine clients read the JSON API; the resolver
default is <code>IPE_REGISTRY_URL</code>. Every entry pins an immutable
<code>rev</code> + <code>sha256</code> (verify-before-trust).</p>
<p>Read paths: <a href="index.json">index.json</a> ·
<a href="advisories/index.json">advisories/index.json</a></p>
<h2>Packages</h2>
<table><tr><th>Package</th><th>Latest</th><th>Publisher</th></tr>
{''.join(rows)}
</table>
{adv_section}
</body></html>
"""


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    out = root / "_site"

    packages: dict[str, dict] = {}
    for path in sorted((root / "packages").glob("*.toml")):
        name, entry = parse_package(path)
        packages[name] = entry
        write_json(out / "packages" / f"{name}.json", entry)

    # index.json: the discovery catalogue (name -> publisher + latest version).
    catalogue = {
        "packages": [
            {
                "name": name,
                "publisher": packages[name]["publisher"],
                "latest": packages[name]["versions"][-1]["version"],
            }
            for name in sorted(packages)
        ]
    }
    write_json(out / "index.json", catalogue)

    advisories: list[dict] = []
    adv_dir = root / "advisories"
    if adv_dir.is_dir():
        for path in sorted(adv_dir.glob("*.toml")):
            record = parse_advisory(path)
            advisories.append(record)
            write_json(out / "advisories" / f"{record['id']}.json", record)
    write_json(
        out / "advisories" / "index.json",
        {"advisories": [{"id": a["id"], "package": a["package"]} for a in advisories]},
    )

    (out / "index.html").write_text(render_html(packages, advisories), encoding="utf-8")

    print(f"generated {len(packages)} package(s), {len(advisories)} advisory(ies) -> {out}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SchemaError as err:
        print(f"schema error: {err}", file=sys.stderr)
        sys.exit(1)
