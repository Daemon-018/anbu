"""Deterministic risk scoring.

The model never owns the number: findings in, score out. See
docs/02-risk-scoring.md for the formula this implements.
"""

from __future__ import annotations

import math

from anbu.models import ApkInfo, Combination, Finding, ScoreResult

SEVERITY_POINTS = {"critical": 30, "high": 15, "medium": 6, "low": 2}
COMBO_BONUS = 12
MAX_COMBOS_SCORED = 3
LLM_ADJUST_BOUNDS = (-8, 12)
INCONCLUSIVE_COVERAGE = 0.35

# (upper bound inclusive, band)
BANDS = (
    (19, "likely_benign"),
    (44, "low"),
    (69, "suspicious"),
    (84, "high"),
    (100, "critical"),
)


def saturate(base_points: int) -> float:
    """Map additive points to 0..100 with diminishing returns."""
    return 100 * (1 - math.exp(-base_points / 45))


def band_for(value: int) -> str:
    for ceiling, band in BANDS:
        if value <= ceiling:
            return band
    return "critical"


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _confidence(info: ApkInfo, findings: list[Finding], inconclusive: bool) -> str:
    if inconclusive:
        return "low"
    if not findings:
        return "high" if info.coverage >= 0.9 else "medium"
    with_evidence = sum(1 for finding in findings if finding.evidence)
    ratio = with_evidence / len(findings)
    if info.coverage >= 0.9 and ratio >= 0.75:
        return "high"
    return "medium"


def score(
    info: ApkInfo,
    findings: list[Finding],
    combos: list[Combination] | None = None,
    llm_adjust: int = 0,
) -> ScoreResult:
    combos = combos or []
    base_points = sum(SEVERITY_POINTS.get(finding.severity, 0) for finding in findings)
    saturated = saturate(base_points)
    combo_bonus = COMBO_BONUS * min(len(combos), MAX_COMBOS_SCORED)
    adjust = _clamp(llm_adjust, *LLM_ADJUST_BOUNDS)
    value = int(round(_clamp(saturated + combo_bonus + adjust, 0, 100)))

    inconclusive = bool(info.packer_hints) or info.coverage < INCONCLUSIVE_COVERAGE
    notes: list[str] = []

    if inconclusive:
        notes.append(
            "inconclusive - dynamic analysis recommended: code was hidden from static "
            "analysis, so a low score is not evidence of safety"
        )
    if info.packer_hints:
        notes.append("packer detected: " + ", ".join(sorted(set(info.packer_hints))))
    if not findings:
        notes.append(
            "no known malicious signals found in the code that could be inspected"
        )
    if info.coverage < 1.0 and not info.packer_hints:
        notes.append(f"static coverage is {info.coverage:.0%} of the DEX")
    if adjust:
        notes.append(f"bounded model adjustment applied: {adjust:+d}")

    return ScoreResult(
        value=value,
        band=band_for(value),
        confidence=_confidence(info, findings, inconclusive),
        coverage=info.coverage,
        inconclusive=inconclusive,
        base_points=base_points,
        saturated=saturated,
        combo_bonus=combo_bonus,
        notes=notes,
    )
