#!/usr/bin/env python3
# Mirror the registry TOML tree to the static JSON read API the ipe CLI fetches:
#   site/packages/<name>.json    (1:1 from packages/<name>.toml; [[version]] -> "versions")
#   site/advisories/<id>.json     (1:1 from the nested advisories/<pkg>/<id>.toml)
#   site/advisories/index.json    ({"advisories": [{"id","package"}]} — object wrapper)
# The CLI parsers (index.rs::parse_entry_json, advisory.rs::parse_advisory_json /
# parse_advisory_index_json) are the authority; this producer fails the build on any
# malformed record so a bad record can never reach the mirror (fail-closed both ends).
import json
import pathlib
import re
import shutil
import sys

try:
    import tomllib
except ModuleNotFoundError:  # local < py3.11
    import tomli as tomllib

ROOT = pathlib.Path(".")
SITE = ROOT / "site"
(SITE / "packages").mkdir(parents=True, exist_ok=True)
(SITE / "advisories").mkdir(parents=True, exist_ok=True)

ID_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]*$")   # closed charset, no leading '-'
SEVERITIES = {"low", "medium", "high", "critical"}
errors = []


def fail(msg):
    errors.append(msg)


def load(p):
    with open(p, "rb") as f:
        return tomllib.load(f)


def nonempty_str(v):
    return isinstance(v, str) and v != ""


def _semver_key(s):
    # Order by (major, minor, patch), then release > pre-release (a pre-release
    # sorts below its final). Falls back to a low key for anything unparsable so a
    # surprising string never crashes the summary — the CLI parser is the real gate.
    core, _, pre = s.partition("-")
    parts = core.split(".")
    nums = []
    for part in parts[:3]:
        nums.append(int(part) if part.isdigit() else -1)
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2], 0 if pre else 1, pre)


def latest_semver(versions):
    return max(versions, key=_semver_key) if versions else None


# --- packages: publisher + versions[] (remap the [[version]] array-of-tables) --------
pkgs = 0
catalogue = []                                  # one summary row per package, for the search UI
for p in sorted((ROOT / "packages").glob("*.toml")):
    raw = load(p)
    versions = raw.get("versions", raw.get("version", []))
    if not isinstance(versions, list) or not versions:
        fail(f"{p}: no [[version]] blocks")
        continue
    if not nonempty_str(raw.get("publisher")):
        fail(f"{p}: missing string `publisher`")
    out_versions = []
    for v in versions:
        if not isinstance(v, dict):
            fail(f"{p}: a [[version]] is not a table")
            continue
        entry = {}
        for key in ("version", "source", "rev", "sha256"):
            if not nonempty_str(v.get(key)):
                fail(f"{p}: a [[version]] missing string `{key}`")
            entry[key] = v.get(key)
        caps = v.get("capabilities", [])
        if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
            fail(f"{p}: `capabilities` is not an array of strings")
            caps = []
        entry["capabilities"] = caps
        if "signature" in v:              # carry the signature bundle through verbatim
            entry["signature"] = v["signature"]
        out_versions.append(entry)
    name = raw.get("name", p.stem)
    (SITE / "packages" / (p.stem + ".json")).write_text(
        json.dumps({"name": name,
                    "publisher": raw.get("publisher"),
                    "versions": out_versions}, indent=2))
    pkgs += 1
    # Summary row for the search UI. The authoritative name is the file stem;
    # capabilities are the union across every published version.
    caps_union = sorted({c for ev in out_versions for c in ev["capabilities"]})
    catalogue.append({
        "name": p.stem,
        "latest_version": latest_semver([ev["version"] for ev in out_versions]),
        "versions_count": len(out_versions),
        "capabilities": caps_union,
        "publisher": raw.get("publisher"),
        "has_advisory": False,          # filled in after the advisory pass below
    })

# --- advisories: nested advisories/<pkg>/<id>.toml -> flat records + object index -----
records = []
seen_ids = set()
for p in sorted((ROOT / "advisories").glob("*/*.toml")):     # nested only
    data = load(p)
    aid, pkg = data.get("id"), data.get("package")
    if not nonempty_str(aid) or not nonempty_str(pkg):
        fail(f"{p}: missing string `id`/`package`")
        continue
    if aid != p.stem:
        fail(f"{p}: id `{aid}` != file stem `{p.stem}`")
    if pkg != p.parent.name:
        fail(f"{p}: package `{pkg}` != parent dir `{p.parent.name}`")
    if not ID_RE.match(aid):
        fail(f"{p}: id `{aid}` outside [A-Za-z0-9._-] / no-leading-'-'")
    if data.get("severity") not in SEVERITIES:
        fail(f"{p}: severity `{data.get('severity')}` not in {sorted(SEVERITIES)}")
    if not nonempty_str(data.get("affected")) or not nonempty_str(data.get("description")):
        fail(f"{p}: empty `affected`/`description`")
    if "fixed_in" in data and not isinstance(data["fixed_in"], str):
        fail(f"{p}: `fixed_in` present but not a string")
    if aid in seen_ids:
        fail(f"{p}: duplicate advisory id `{aid}`")
    seen_ids.add(aid)
    rec = {"id": aid, "package": pkg, "severity": data.get("severity"),
           "affected": data.get("affected"), "description": data.get("description")}
    if nonempty_str(data.get("fixed_in")):
        rec["fixed_in"] = data["fixed_in"]
    (SITE / "advisories" / (aid + ".json")).write_text(json.dumps(rec, indent=2))
    records.append({"id": aid, "package": pkg})

(SITE / "advisories" / "index.json").write_text(
    json.dumps({"advisories": sorted(records, key=lambda r: r["id"])}, indent=2))

# --- catalogue: one summary row per package for the static search UI -----------------
advised = {r["package"] for r in records}
for row in catalogue:
    row["has_advisory"] = row["name"] in advised
catalogue.sort(key=lambda r: r["name"])
(SITE / "catalogue.json").write_text(json.dumps(catalogue, indent=2))

# --- landing page: static search UI over catalogue.json (checked-in source) ----------
shutil.copyfile(ROOT / "scripts" / "index.html", SITE / "index.html")
(SITE / "index.json").write_text(json.dumps(
    {"registry": "ipe-registry",
     "endpoints": ["/packages/<name>.json", "/advisories/index.json",
                   "/advisories/<id>.json", "/catalogue.json"]},
    indent=2))

if errors:
    print("build_site: FAIL — malformed registry data:", file=sys.stderr)
    for e in errors:
        print("  " + e, file=sys.stderr)
    sys.exit(1)
print(f"built {pkgs} package JSON, {len(records)} advisory JSON, "
      f"{len(catalogue)} catalogue rows")
