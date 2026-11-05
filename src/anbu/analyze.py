"""One-function pipeline: validate, extract, rank, rule, interpret, score, report."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from anbu.extract import load_artifacts, load_signals
from anbu.ingest import IngestResult, validate_apk
from anbu.interpret import Interpretation, LlmClient, interpret
from anbu.models import ApkInfo, Combination, Finding, ScoreResult
from anbu.rank import RankedClass, rank_classes, slices_for
from anbu.report import build_report
from anbu.rules import load_pack, run_combos, run_rules
from anbu.score import score as score_findings


@dataclass
class Analysis:
    ingest: IngestResult
    info: ApkInfo
    findings: list[Finding]
    combos: list[Combination]
    ranked: list[RankedClass]
    interpretation: Interpretation
    score: ScoreResult
    report: dict[str, Any]


def analyze(
    path: str | Path,
    rank_limit: int = 25,
    llm: LlmClient | None = None,
    max_llm_slices: int = 8,
) -> Analysis:
    ingest = validate_apk(path)
    pack = load_pack()
    signals = load_signals()
    artifacts = load_artifacts(ingest, signals)
    info = artifacts.info

    rule_findings = run_rules(info, pack)
    findings = list(rule_findings)
    findings.sort(key=lambda finding: _severity_key(finding.severity))
    combos = run_combos(findings, pack)
    ranked = rank_classes(
        artifacts.dexes,
        artifacts.dx,
        signals.get("rank_weights", []),
        signals.get("rank_keywords", []),
        archive_names=info.dex_names,
        limit=rank_limit,
        ignore_prefixes=signals.get("rank_ignore_prefixes", ()),
    )

    interpretation = Interpretation()
    if llm is not None and ranked:
        slices = slices_for(artifacts.dexes, artifacts.dx, ranked[:max_llm_slices])
        interpretation = interpret(info, slices, rule_findings, client=llm)
        if interpretation.findings:
            findings = findings + interpretation.findings
            findings.sort(key=lambda finding: _severity_key(finding.severity))
            combos = run_combos(findings, pack)

    score_result = score_findings(info, findings, combos)
    report = build_report(
        info,
        findings,
        combos,
        score_result,
        ranked=ranked,
        extra_notes=interpretation.notes,
    )
    return Analysis(
        ingest=ingest,
        info=info,
        findings=findings,
        combos=combos,
        ranked=ranked,
        interpretation=interpretation,
        score=score_result,
        report=report,
    )


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _severity_key(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 4)
