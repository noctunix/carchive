"""Guards against the source tree referencing the design document instead of standing on its
own.

Comments and docstrings must carry enough context by themselves; a pointer to a section
number or file that is not part of the published repository rots the moment that document is
renamed, moved or simply not there for a reader of the code alone.
"""

from __future__ import annotations

from pathlib import Path

SRC_ROOT = Path(__file__).parent.parent / "src"

_FORBIDDEN_NEEDLES = ("§", "concept.md", "concept §", "docs/")


def find_doc_references(src_root: Path) -> list[str]:
    """Find every `.py` file under `src_root` that references the design document.

    Args:
        src_root: the source tree to scan.

    Returns:
        One human-readable finding per `(file, needle)` match, empty if the tree is clean.
    """
    findings = []
    for py_file in sorted(src_root.rglob("*.py")):
        text = py_file.read_text(encoding="utf-8").lower()
        for needle in _FORBIDDEN_NEEDLES:
            if needle in text:
                findings.append(f"{py_file.relative_to(src_root)} contains {needle!r}")
    return findings


def test_source_does_not_reference_the_design_document() -> None:
    findings = find_doc_references(SRC_ROOT)
    assert not findings, "design-document references leaked into source:\n" + "\n".join(findings)
