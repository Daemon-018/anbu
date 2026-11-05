from __future__ import annotations

import pytest

from anbu.models import Combination, Evidence, Finding
from anbu.score import band_for, saturate, score
from tests.conftest import make_info


def finding(identifier: str, severity: str, category: str = "test", evidence: bool = True) -> Finding:
    return Finding(
        id=identifier,
        title=f"{severity} finding",
        severity=severity,
        category=category,
        description="d",
        rationale="r",
        evidence=[Evidence("classes.dex", "Lfoo;->bar")] if evidence else [],
        confidence=0.9,
        source="rule",
        verified=True,
    )


def test_saturating_curve_matches_the_documented_calibration():
    assert saturate(45) == pytest.approx(63.2, abs=0.1)
    assert saturate(90) == pytest.approx(86.5, abs=0.1)
    assert saturate(150) == pytest.approx(96.4, abs=0.1)
    assert saturate(0) == 0


@pytest.mark.parametrize(
    "value, band",
    [(0, "likely_benign"), (19, "likely_benign"), (20, "low"), (44, "low"),
     (45, "suspicious"), (69, "suspicious"), (70, "high"), (84, "high"),
     (85, "critical"), (100, "critical")],
)
def test_band_boundaries(value, band):
    assert band_for(value) == band


def test_score_is_monotonic_and_saturates_below_100():
    info = make_info()
    low = score(info, [finding("A", "low")])
    high = score(info, [finding("A", "high"), finding("B", "critical")])
    many = score(info, [finding(f"F{i}", "critical") for i in range(20)])
    assert low.value < high.value < many.value
    assert many.value <= 100


def test_combos_add_a_bounded_bonus():
    info = make_info()
    findings = [finding("A", "medium")]
    none = score(info, findings, [])
    one = score(info, findings, [Combination("X", "x", "r", [])])
    four = score(info, findings, [Combination(str(i), "x", "r", []) for i in range(4)])
    assert one.value == none.value + 12
    assert four.value == none.value + 36


def test_model_adjustment_is_clamped():
    info = make_info()
    findings = [finding("A", "medium")]
    base = score(info, findings).value
    assert score(info, findings, llm_adjust=-100).value == max(0, base - 8)
    assert score(info, findings, llm_adjust=100).value == min(100, base + 12)


def test_packed_app_is_inconclusive_even_with_a_low_score():
    info = make_info(packer_hints=["jiagu"], coverage=0.3)
    result = score(info, [])
    assert result.inconclusive is True
    assert result.confidence == "low"
    assert any("inconclusive" in note for note in result.notes)


def test_low_coverage_without_packer_is_inconclusive():
    result = score(make_info(coverage=0.2), [finding("A", "low")])
    assert result.inconclusive is True


def test_findings_without_evidence_lower_confidence():
    confident = score(make_info(), [finding("A", "high")])
    shaky = score(make_info(), [finding("A", "high", evidence=False)])
    assert confident.confidence == "high"
    assert shaky.confidence == "medium"


def test_empty_scan_says_no_known_signals_not_safe():
    result = score(make_info(), [])
    assert result.value == 0
    assert result.band == "likely_benign"
    assert any("not evidence of safety" in note or "no known malicious" in note for note in result.notes)
