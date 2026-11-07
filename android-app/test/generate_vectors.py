#!/usr/bin/env python3
"""Generate parity vectors for android-app/test/ScoreMathTest.java.

Every row comes from the real ``anbu.score`` implementation, so the Java port
is checked against the desktop tool rather than against a second hand-written
copy of the formula. Run from the repository root after changing score.py:

    python android-app/test/generate_vectors.py

The generated TSV files are committed and read by the plain-JDK test.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))

from anbu.models import ApkInfo, Evidence, Finding  # noqa: E402
from anbu.score import (  # noqa: E402
    BANDS,
    _confidence,
    band_for,
    saturate,
    score,
)


def apk(coverage: float, packers: list[str] | None = None) -> ApkInfo:
    return ApkInfo(
        path="fixture.apk",
        sha256="0" * 64,
        size=1,
        package="test.fixture",
        label="Fixture",
        version_name="1.0",
        version_code="1",
        min_sdk=24,
        target_sdk=34,
        coverage=coverage,
        packer_hints=list(packers or []),
    )


def finding(severity: str, with_evidence: bool) -> Finding:
    return Finding(
        id=f"T-{severity}",
        title="test",
        severity=severity,
        category="test",
        description="test",
        rationale="test",
        evidence=[Evidence("AndroidManifest.xml", "x")] if with_evidence else [],
    )


def write_scores(path: Path) -> int:
    cases = [
        [],
        ["low"],
        ["medium"],
        ["high"],
        ["critical"],
        ["low", "low"],
        ["medium", "high"],
        ["high", "high"],
        ["critical", "high"],
        ["critical", "critical"],
        ["critical", "high", "medium", "low"],
        ["critical"] * 5,
        ["high"] * 8,
        ["medium"] * 12,
        ["low"] * 20,
        ["critical", "high", "medium", "low", "high", "critical"],
    ]
    combos = [0, 1, 2, 3, 4, 7]
    adjusts = [-20, -8, -1, 0, 1, 12, 20]

    rows = []
    for severities in cases:
        findings = [finding(s, True) for s in severities]
        for combo_count in combos:
            for adjust in adjusts:
                result = score(apk(1.0), findings, [None] * combo_count, adjust)
                rows.append(
                    (
                        ",".join(severities) or "-",
                        combo_count,
                        adjust,
                        result.base_points,
                        repr(result.saturated),
                        result.combo_bonus,
                        result.value,
                        result.band,
                    )
                )

    with path.open("w", encoding="utf-8") as handle:
        handle.write("severities\tcombos\tadjust\tbase\tsaturated\tbonus\tvalue\tband\n")
        for row in rows:
            handle.write("\t".join(str(value) for value in row) + "\n")
    return len(rows)


def write_bands(path: Path) -> int:
    with path.open("w", encoding="utf-8") as handle:
        handle.write("value\tband\n")
        for value in range(0, 101):
            handle.write(f"{value}\t{band_for(value)}\n")
    return 101


def write_confidence(path: Path) -> int:
    coverages = [0.0, 0.1, 0.34, 0.35, 0.5, 0.89, 0.9, 0.99, 1.0]
    counts = [0, 1, 2, 4, 10]
    fractions = [0.0, 0.25, 0.5, 0.74, 0.75, 0.8, 1.0]
    rows = []
    for coverage in coverages:
        for count in counts:
            for fraction in fractions:
                with_evidence = round(fraction * count)
                findings = [
                    finding("high", index < with_evidence) for index in range(count)
                ]
                for inconclusive in (False, True):
                    result = _confidence(apk(coverage), findings, inconclusive)
                    rows.append(
                        (
                            repr(coverage),
                            count,
                            with_evidence,
                            str(inconclusive).lower(),
                            result,
                        )
                    )

    with path.open("w", encoding="utf-8") as handle:
        handle.write("coverage\tfindings\tevidence\tinconclusive\tconfidence\n")
        for row in rows:
            handle.write("\t".join(str(value) for value in row) + "\n")
    return len(rows)


def write_inconclusive(path: Path) -> int:
    rows = []
    for has_packers in (False, True):
        for coverage in (0.0, 0.1, 0.34, 0.35, 0.5, 0.9, 1.0):
            packers = ["packer"] if has_packers else []
            result = score(apk(coverage, packers), [])
            rows.append(
                (str(has_packers).lower(), repr(coverage), str(result.inconclusive).lower())
            )

    with path.open("w", encoding="utf-8") as handle:
        handle.write("packers\tcoverage\tinconclusive\n")
        for row in rows:
            handle.write("\t".join(row) + "\n")
    return len(rows)


def main() -> None:
    scores = write_scores(HERE / "score-vectors.tsv")
    bands = write_bands(HERE / "band-vectors.tsv")
    confidence = write_confidence(HERE / "confidence-vectors.tsv")
    inconclusive = write_inconclusive(HERE / "inconclusive-vectors.tsv")
    print(f"score-vectors.tsv        {scores} rows")
    print(f"band-vectors.tsv         {bands} rows")
    print(f"confidence-vectors.tsv   {confidence} rows")
    print(f"inconclusive-vectors.tsv {inconclusive} rows")
    assert len(BANDS) == 5 and saturate(45) > 0


if __name__ == "__main__":
    main()
