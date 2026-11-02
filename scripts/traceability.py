#!/usr/bin/env python3
"""Requirement-traceability check (TESTING.md TEST-01, PRD NFR-06).

Every acceptance criterion (FR-xx ACy) and every NFR-xx / SEC-xx requirement in the
PRD must either
  * be named on a `Covers:` line in test code (Rust `// Covers: FR-02 AC1, SEC-13`,
    Python `# Covers: FR-03 AC4`), or
  * be listed in docs/traceability.toml with a category and a written reason
    (blocked, release-checklist, ci-job, not-applicable).

Exit code 0 when every requirement is accounted for, 1 otherwise. A BLOCKED item is
reported loudly; it is never counted as passing (TEST-10).

Usage: scripts/traceability.py [--report]
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRD = ROOT / "Keystone PRD6 - final.md"
EXCEPTIONS = ROOT / "docs" / "traceability.toml"
SEARCH_DIRS = ["keystone-core", "keystone-gui", "keystone-testkit", "fuzz"]
SOURCE_SUFFIXES = {".rs", ".py", ".sh", ".go"}
CATEGORIES = {"blocked", "release-checklist", "ci-job", "not-applicable"}


def prd_requirements() -> list[str]:
    """All requirement IDs in PRD order."""
    text = PRD.read_text(encoding="utf-8")
    ids: list[str] = []
    current_fr = None
    for line in text.splitlines():
        heading = re.match(r"^\*\*(FR-\d{2}) ", line)
        if heading:
            current_fr = heading.group(1)
            continue
        criterion = re.match(r"^- (AC\d+):", line)
        if criterion and current_fr:
            ids.append(f"{current_fr} {criterion.group(1)}")
            continue
        if line.startswith("## "):
            current_fr = None
        row = re.match(r"^\| ((?:NFR|SEC)-\d{2}) \|", line)
        if row:
            ids.append(row.group(1))
    return ids


def parse_covers(text: str) -> set[str]:
    """IDs named on one `Covers:` line. `FR-12 AC1-AC4` and `FR-03 AC1, AC2` expand."""
    found: set[str] = set()
    current_fr = None
    tokens = re.findall(r"(?:FR|NFR|SEC)-\d{2}|AC\d+\s*[-–]\s*AC\d+|AC\d+", text)
    for token in tokens:
        if token.startswith("FR-"):
            current_fr = token
            continue
        if token.startswith(("NFR-", "SEC-")):
            found.add(token)
            current_fr = None
            continue
        if current_fr is None:
            continue
        span = re.match(r"AC(\d+)\s*[-–]\s*AC(\d+)", token)
        if span:
            for number in range(int(span.group(1)), int(span.group(2)) + 1):
                found.add(f"{current_fr} AC{number}")
        else:
            found.add(f"{current_fr} {token}")
    # A bare `FR-xx` without an AC does not cover any criterion on purpose.
    return found


def collected_covers() -> dict[str, list[str]]:
    covers: dict[str, list[str]] = {}
    for directory in SEARCH_DIRS:
        base = ROOT / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in SOURCE_SUFFIXES or "target" in path.parts:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                match = re.search(r"(?://|#)\s*Covers:\s*(.+)$", line)
                if not match:
                    continue
                for requirement in parse_covers(match.group(1)):
                    where = f"{path.relative_to(ROOT)}:{number}"
                    covers.setdefault(requirement, []).append(where)
    return covers


def exceptions() -> dict[str, tuple[str, str]]:
    if not EXCEPTIONS.exists():
        return {}
    data = tomllib.loads(EXCEPTIONS.read_text(encoding="utf-8"))
    result: dict[str, tuple[str, str]] = {}
    for category, entries in data.items():
        if category not in CATEGORIES:
            raise SystemExit(f"unknown category [{category}] in {EXCEPTIONS}")
        for requirement, reason in entries.items():
            if not str(reason).strip():
                raise SystemExit(f"{requirement} in [{category}] needs a written reason")
            result[requirement] = (category, str(reason))
    return result


def main() -> int:
    report = "--report" in sys.argv
    requirements = prd_requirements()
    covers = collected_covers()
    excepted = exceptions()
    missing: list[str] = []
    unknown = sorted(set(covers) - set(requirements))
    blocked: list[str] = []

    for requirement in requirements:
        tested = requirement in covers
        if requirement in excepted:
            category, reason = excepted[requirement]
            if category == "blocked":
                blocked.append(requirement)
            if report:
                status = "tested + " if tested else ""
                print(f"{requirement:12} {status}{category.upper()}: {reason}")
            continue
        if tested:
            if report:
                print(f"{requirement:12} tested ({len(covers[requirement])} places)")
            continue
        missing.append(requirement)

    print(f"{len(requirements)} requirements; {len(requirements) - len(missing)} accounted for.")
    for requirement in blocked:
        print(f"BLOCKED: {requirement}: {excepted[requirement][1]}")
    for requirement in unknown:
        print(f"WARNING: `Covers:` names {requirement}, which is not in the PRD: "
              + ", ".join(covers[requirement][:3]))
    if missing:
        print("MISSING: no test and no documented exception for:")
        for requirement in missing:
            print(f"  {requirement}")
        return 1
    if unknown:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
