"""`anbu` command line: one APK in, one report out."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from anbu import __version__
from anbu.analyze import Analysis, analyze
from anbu.ingest import IngestError
from anbu.interpret import client_from_env
from anbu.models import BAND_RANK
from anbu.report import write_html, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="anbu",
        description="Static Android APK risk analysis with explainable findings.",
    )
    parser.add_argument("--version", action="version", version=f"ANBU {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan", help="analyse one APK and write JSON/HTML reports"
    )
    scan.add_argument("apk", help="path to the .apk file")
    scan.add_argument("--out", help="directory for reports (default: out/)")
    scan.add_argument("--json", dest="json_path", help="explicit JSON report path")
    scan.add_argument("--html", dest="html_path", help="explicit HTML report path")
    scan.add_argument(
        "--fail-on",
        choices=("low", "suspicious", "high", "critical"),
        help="exit with status 3 when the band reaches this level",
    )
    scan.add_argument(
        "--llm",
        action="store_true",
        help="add a model pass over the top ranked classes "
        "(needs ANBU_LLM_BASE_URL and ANBU_LLM_MODEL)",
    )
    scan.add_argument(
        "--max-llm-slices",
        type=int,
        default=8,
        metavar="N",
        help="number of ranked classes to send to the model (default: 8)",
    )
    return parser


def _summary(analysis: Analysis) -> str:
    info = analysis.info
    score = analysis.score
    lines = [
        f"Package : {info.package or '?'} ({info.label or 'no label'})",
        f"SHA-256 : {info.sha256}",
        f"Score   : {score.value}/100 - {score.band.replace('_', ' ')}"
        f" (confidence: {score.confidence}, coverage: {score.coverage:.0%})",
    ]
    if score.inconclusive:
        lines.append("Verdict : INCONCLUSIVE - code was hidden from static analysis")
    if analysis.combos:
        lines.append("Patterns: " + ", ".join(combo.id for combo in analysis.combos))
    if analysis.interpretation.used_model:
        lines.append(
            "Model   : "
            f"{len(analysis.interpretation.findings)} verified finding(s), "
            "score unchanged by the model"
        )
    if analysis.findings:
        lines.append("Top findings:")
        for finding in analysis.findings[:5]:
            lines.append(f"  [{finding.severity:8}] {finding.id} {finding.title}")
        if len(analysis.findings) > 5:
            lines.append(f"  ... {len(analysis.findings) - 5} more in the report")
    else:
        lines.append("Findings: none. No known malicious signals, not a guarantee of safety.")
    return "\n".join(lines)


def _paths(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.json_path or args.html_path:
        base = Path(args.json_path or args.html_path)
        json_path = Path(args.json_path) if args.json_path else base.with_suffix(".json")
        html_path = Path(args.html_path) if args.html_path else base.with_suffix(".html")
        return json_path, html_path
    out_dir = Path(args.out or "out")
    stem = Path(args.apk).stem
    return out_dir / f"{stem}.json", out_dir / f"{stem}.html"


def _gate(analysis: Analysis, fail_on: str) -> int:
    if BAND_RANK[analysis.score.band] >= BAND_RANK[fail_on]:
        print(
            f"Failing: band {analysis.score.band} reached --fail-on {fail_on}",
            file=sys.stderr,
        )
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return 2

    client = None
    if args.llm:
        client = client_from_env()
        if client is None:
            print(
                "anbu: --llm needs ANBU_LLM_BASE_URL and ANBU_LLM_MODEL "
                "(optionally ANBU_LLM_API_KEY)",
                file=sys.stderr,
            )
            return 2

    try:
        analysis = analyze(args.apk, llm=client, max_llm_slices=args.max_llm_slices)
    except IngestError as exc:
        print(f"anbu: refused to parse {args.apk}: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"anbu: file not found: {args.apk}", file=sys.stderr)
        return 1

    json_path, html_path = _paths(args)
    write_json(analysis.report, json_path)
    write_html(analysis.report, html_path)

    print(_summary(analysis))
    print(f"JSON    : {json_path}")
    print(f"HTML    : {html_path}")

    if args.fail_on:
        return _gate(analysis, args.fail_on)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
