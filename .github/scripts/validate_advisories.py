#!/usr/bin/env python3
"""Pull-request checks over the advisory database that the site builder does not do.

`scripts/build_site.py` is the schema source of truth: it parses every nested
`advisories/<package>/<id>.toml`, validates it fail-closed (id equals the file
stem, package equals the parent directory, severity enum, non-empty `affected`
and `description`, string `fixed_in`), and mirrors the tree to JSON. The
admission gate runs it first, so schema and layout are already enforced there.

This script adds the checks that only make sense at admission time:

  * no advisory is mis-placed — a `.toml` sitting flat under `advisories/`
    instead of nested under a package directory is rejected, not silently
    ignored (the site builder's nested glob would skip it),
  * every advisory names a package that has an entry under `packages/`, and
  * no advisory published on the base branch has been deleted (advisories are
    immutable — a mistaken one is amended, not removed).

Fail-closed: any violation exits non-zero and blocks the merge.

Usage:
    validate_advisories.py --advisories <dir> --packages <dir> [--base-advisories <dir>]

`--base-advisories` is the `advisories/` tree as it exists on the target branch.
When given, deletion of a published advisory is rejected.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib


def load_package_of(path: Path) -> str | None:
    """Return the advisory's declared package, or None if the file is unreadable."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    pkg = data.get("package")
    return pkg if isinstance(pkg, str) and pkg else None


def nested_advisories(root: Path) -> list[Path]:
    return sorted(root.glob("*/*.toml"))


def rel_id(path: Path) -> str:
    """A stable identity for an advisory: `<package>/<id>` from its nested path."""
    return f"{path.parent.name}/{path.stem}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--advisories", required=True, type=Path)
    ap.add_argument("--packages", required=True, type=Path)
    ap.add_argument("--base-advisories", type=Path, default=None)
    args = ap.parse_args()

    package_names = {p.stem for p in args.packages.glob("*.toml")}
    current = nested_advisories(args.advisories)

    errs: list[str] = []

    # Layout: every advisory lives nested under a package directory. A `.toml`
    # sitting flat directly under advisories/ is a mis-placement the site
    # builder's nested glob would silently skip; reject it here so a bad layout
    # can never merge unnoticed.
    for stray in sorted(args.advisories.glob("*.toml")):
        errs.append(
            f"{stray}: advisory must be nested at advisories/<package>/<id>.toml, "
            f"not flat under advisories/"
        )

    # Every advisory must name a package that exists in the index. The site builder
    # checks package == parent-dir but not that the package is real; this closes
    # the gap so an advisory can never dangle against a non-existent package.
    for path in current:
        pkg = load_package_of(path)
        if pkg is None:
            errs.append(f"{path}: unreadable or missing string `package`")
        elif pkg not in package_names:
            errs.append(f"{path}: `package` {pkg!r} has no entry under packages/")

    # Immutability: an advisory published on the base branch must still be present.
    if args.base_advisories and args.base_advisories.exists():
        base_ids = {rel_id(p) for p in nested_advisories(args.base_advisories)}
        now_ids = {rel_id(p) for p in current}
        for gone in sorted(base_ids - now_ids):
            errs.append(f"{gone}.toml: deleting a published advisory is forbidden (immutable)")

    if errs:
        print("advisory admission: REJECTED\n", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"advisory admission: OK — {len(current)} advisory file(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
