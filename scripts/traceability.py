#!/usr/bin/env python3
"""Requirement-traceability check (TESTING.md TEST-01, PRD NFR-06).

Every acceptance criterion (FR-xx ACy) and every NFR-xx / SEC-xx requirement in the
PRD must either
  * be named on a `Covers:` line in test code (Rust `// Covers: FR-02 AC1, SEC-13`,
    Python `# Covers: FR-03 AC4`), or
  * be listed in docs/traceability.toml with a category and a written reason
    (blocked, release-checklist, ci-job, not-applicable).

Test code is (see `test_code`): Rust files in a crate's `tests/` folder, Rust
`#[cfg(test)]` modules (inline, or a file declared as `#[cfg(test)] mod tests;`),
fuzz targets, Python `test_*.py` files, and Go or shell helpers in a `tests/` folder
that a counted Rust test names. A `Covers:` comment anywhere else (application code,
examples, scripts, a stray file) is not counted; it is listed with --report.

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


COVERS = re.compile(r"(?://|#)\s*Covers:\s*(.+)$")
# `#[cfg(test)]` or `#[cfg(all(..., test, ...))]`: compiled only for tests.
# (`cfg(any(test, ...))` is not: that code is also part of a normal build.)
CFG_TEST = re.compile(r"#\[cfg\((?:test|all\([^\]]*\btest\b[^\]]*\))\)\]")
MOD_DECL = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])")


PLAIN = re.compile(r"[^/\"'rbc]+")
RAW_STRING = re.compile(r'[bc]?r(#*)"')
CHAR_LITERAL = re.compile(r"b?'(?:\\(?:u\{[0-9A-Fa-f_]*\}|x[0-9A-Fa-f]{2}|.)|[^\\'\n])'")


def blank_rust(text: str) -> str:
    """`text` with comments, string literals and character literals replaced by
    spaces (newlines kept), so braces and attributes can be read reliably.
    Lifetimes and labels ('a) are code and stay."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        plain = PLAIN.match(text, i)
        if plain:
            out.append(plain.group())
            i = plain.end()
            continue
        prev = text[i - 1] if i else " "
        ident_before = prev.isalnum() or prev == "_"
        raw = None if ident_before else RAW_STRING.match(text, i)
        char = CHAR_LITERAL.match(text, i)
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
        elif text.startswith("/*", i):
            depth, end = 1, i + 2
            while end < n and depth:
                if text.startswith("/*", end):
                    depth, end = depth + 1, end + 2
                elif text.startswith("*/", end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
        elif raw:
            close = '"' + raw.group(1)
            end = text.find(close, raw.end())
            end = n if end < 0 else end + len(close)
        elif text[i] == '"' or (
            not ident_before and text[i] in "bc" and text.startswith('"', i + 1)
        ):
            end = text.index('"', i) + 1
            while end < n and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end = min(end + 1, n)
        elif char and not (text[i] == "b" and ident_before):
            end = char.end()
        else:
            out.append(text[i])
            i += 1
            continue
        out.append(re.sub(r"[^\n]", " ", text[i:end]))
        i = end
    return "".join(out)


def module_dir(path: Path) -> Path:
    """Directory of the files of the child modules declared in `path`."""
    if path.name in {"mod.rs", "lib.rs", "main.rs"}:
        return path.parent
    return path.parent / path.stem


def cfg_test_parts(path: Path) -> tuple[set[int], list[Path]]:
    """Lines of `path` inside `#[cfg(test)] mod name { ... }` blocks, and the files of
    `#[cfg(test)] mod name;` declarations."""
    code = blank_rust(path.read_text(encoding="utf-8"))
    lines = code.splitlines()
    test_lines: set[int] = set()
    test_files: list[Path] = []
    pending = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if CFG_TEST.fullmatch(stripped):
            pending = True
            continue
        if not pending or not stripped or stripped.startswith("#["):
            continue
        pending = False
        declaration = MOD_DECL.match(stripped)
        if not declaration:
            continue
        name, kind = declaration.groups()
        if kind == ";":
            directory = module_dir(path)
            for candidate in (directory / f"{name}.rs", directory / name / "mod.rs"):
                if candidate.exists():
                    test_files.append(candidate)
                    break
            continue
        # Inline module: from this line to its matching closing brace.
        depth = 0
        end = index
        for end in range(index, len(lines)):
            depth += lines[end].count("{") - lines[end].count("}")
            if depth <= 0:
                break
        test_lines.update(range(index + 1, end + 2))
    return test_lines, test_files


def test_code() -> dict[Path, set[int] | None]:
    """The files that hold test code. `None` means the whole file; a set lists the
    lines (1-based) of the `#[cfg(test)]` modules in an ordinary source file.

    Counted (TEST-01): Rust files in a crate's `tests/` folder, Rust `#[cfg(test)]`
    modules (inline, or a file declared as `#[cfg(test)] mod tests;`), fuzz targets,
    Python `test_*.py` files, and Go or shell helpers in a `tests/` folder that a
    counted Rust test names. Nothing else: a `Covers:` comment in application code,
    an example, a script or a stray file does not count.
    """
    found: dict[Path, set[int] | None] = {}
    helpers: list[Path] = []
    for directory in SEARCH_DIRS:
        base = ROOT / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            parts = path.relative_to(ROOT).parts
            if path.suffix not in SOURCE_SUFFIXES or "target" in parts or not path.is_file():
                continue
            in_tests = len(parts) > 2 and parts[1] == "tests"
            if path.suffix == ".py":
                if path.name.startswith("test_"):
                    found[path] = None
            elif path.suffix in {".go", ".sh"}:
                if in_tests:
                    helpers.append(path)
            elif in_tests or parts[:2] == ("fuzz", "fuzz_targets"):
                found[path] = None
            elif len(parts) > 2 and parts[1] == "src":
                queue = [path]
                while queue:
                    current = queue.pop()
                    lines, files = cfg_test_parts(current)
                    if lines and found.get(current, set()) is not None:
                        found.setdefault(current, set()).update(lines)
                    for child in files:
                        found[child] = None
                        queue.append(child)
    rust_tests = [path for path, lines in found.items() if path.suffix == ".rs"]
    for helper in helpers:
        if any(helper.name in path.read_text(encoding="utf-8") for path in rust_tests):
            found[helper] = None
    return found


def collected_covers() -> dict[str, list[str]]:
    covers: dict[str, list[str]] = {}
    for path, lines in sorted(test_code().items()):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if lines is not None and number not in lines:
                continue
            match = COVERS.search(line)
            if not match:
                continue
            for requirement in parse_covers(match.group(1)):
                where = f"{path.relative_to(ROOT)}:{number}"
                covers.setdefault(requirement, []).append(where)
    return covers


def ignored_covers() -> list[str]:
    """`Covers:` lines outside test code (they do not count)."""
    counted = test_code()
    ignored: list[str] = []
    for directory in SEARCH_DIRS:
        base = ROOT / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            parts = path.relative_to(ROOT).parts
            if path.suffix not in SOURCE_SUFFIXES or "target" in parts or not path.is_file():
                continue
            lines = counted.get(path, set()) if path in counted else set()
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if COVERS.search(line) and lines is not None and number not in lines:
                    ignored.append(f"{path.relative_to(ROOT)}:{number}")
    return ignored


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
    ignored = ignored_covers()
    if ignored:
        print(f"NOTE: {len(ignored)} `Covers:` line(s) outside test code were not counted"
              + (":" if report else " (--report lists them)."))
        if report:
            for where in ignored:
                print(f"  not test code: {where}")
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
