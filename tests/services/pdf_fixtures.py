"""Builds synthetic Data Dictionary PDFs, shaped like the real ones, for catalog tests."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Table, TableStyle

CONTINUOUS_HEADER = (
    "Key",
    "Data Point Name",
    "Description",
    "Measurement Unit",
    "Tech. Data Type",
    "Data Cluster",
)
HISTORICAL_HEADER = (
    "Key",
    "Data Point Name",
    "Description",
    "Measurement Unit",
    "Tech. Data Type",
)

_STYLES = getSampleStyleSheet()


def build_dictionary_pdf(
    path: Path,
    *,
    title: str,
    header: tuple[str, ...],
    rows: list[list[str]],
) -> None:
    """Write a multi-page table PDF: a title-only lead page, then a `GRID`-styled table.

    `reportlab`'s own pagination (`Table(..., repeatRows=1)`) splits the table across pages
    and repeats the header row, matching the real dictionaries' per-page header.
    """
    doc = SimpleDocTemplate(str(path), pagesize=A4)
    table = Table([list(header), *rows], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]
        )
    )
    doc.build([Paragraph(title, _STYLES["Title"]), PageBreak(), table])
