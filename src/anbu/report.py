"""Render the JSON model and a self-contained HTML report.

The HTML has no external assets so it can be opened offline on the phone that
produced the scan, and it preserves the same evidence quotes as the JSON.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from anbu import __version__
from anbu.models import ApkInfo, Combination, Finding, ScoreResult
from anbu.rank import RankedClass

BAND_TEXT = {
    "likely_benign": (
        "No malicious signals found",
        "Nothing known-malicious was found in the code that could be inspected. "
        "That is not a guarantee of safety.",
    ),
    "low": (
        "Some risky capabilities, no clear malicious intent",
        "The app can do a few sensitive things, but they appear consistent with a "
        "legitimate purpose. Install only if you trust where it came from.",
    ),
    "suspicious": (
        "Behaviours commonly abused by malware",
        "Several capabilities are typical of malicious apps. Install with caution, "
        "preferably in a sandbox or on a spare device.",
    ),
    "high": (
        "Strong indicators of malicious behaviour",
        "The combination of capabilities and code references is hard to explain as a "
        "legitimate app. Avoid installing.",
    ),
    "critical": (
        "Multiple coordinated malicious behaviours detected",
        "This looks like a coordinated attack tool. Do not install; if it is already "
        "installed, remove it and check the device for other changes.",
    ),
}

CATEGORY_LABELS = {
    "sms_interception": "SMS interception",
    "sms_fraud": "SMS fraud",
    "accessibility_abuse": "Accessibility abuse",
    "overlay_attack": "Overlay attack",
    "dropper": "Second-stage dropper",
    "dynamic_code": "Runtime code loading",
    "device_admin": "Device administration",
    "ransomware": "Ransomware",
    "persistence": "Persistence",
    "data_harvesting": "Personal-data harvesting",
    "reconnaissance": "Device reconnaissance",
    "surveillance": "Surveillance",
    "stalkerware": "Stalkerware",
    "spyware": "Spyware",
    "fingerprinting": "Device fingerprinting",
    "credential_theft": "Credential theft",
    "notification_interception": "Notification interception",
    "execution": "Shell execution",
    "webview": "WebView bridge",
    "obfuscation": "Obfuscation",
    "anti_analysis": "Anti-analysis",
    "c2": "Command and control",
    "exfiltration": "Data exfiltration",
    "transport": "Transport security",
    "credential_leak": "Credential leak",
    "identity": "Signing identity",
    "posture": "Build posture",
    "attack_surface": "Exported attack surface",
}

LIMITATIONS = [
    "Static analysis cannot see server-delivered logic, runtime-decrypted payloads, "
    "native code inside .so files, or behaviour gated on device or region checks.",
    "Absence of signals is not safety. The correct reading is 'no known malicious "
    "signals'.",
    "The score is a triage aid, not a guarantee and not a legal determination.",
]


def capability_summary(findings: list[Finding]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1
    return [
        {"category": category, "label": CATEGORY_LABELS.get(category, category), "findings": count}
        for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def verdict(score: ScoreResult) -> dict[str, Any]:
    headline, advice = BAND_TEXT[score.band]
    if score.inconclusive:
        advice = (
            "This app hides code from static analysis, so no score can be trusted. "
            "Treat it as unknown and request a dynamic scan before installing."
        )
    return {
        "band": score.band,
        "value": score.value,
        "headline": headline,
        "advice": advice,
        "confidence": score.confidence,
        "coverage": score.coverage,
        "inconclusive": score.inconclusive,
    }


def build_report(
    info: ApkInfo,
    findings: list[Finding],
    combos: list[Combination],
    score: ScoreResult,
    ranked: list[RankedClass] | None = None,
    extra_notes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tool": {"name": "anbu", "version": __version__},
        "apk": info.to_dict(),
        "score": score.to_dict(),
        "verdict": verdict(score),
        "capabilities": capability_summary(findings),
        "findings": [finding.to_dict() for finding in findings],
        "combos": [combo.to_dict() for combo in combos],
        "ranked_classes": [item.to_dict() for item in (ranked or [])],
        "warnings": list(info.warnings) + list(score.notes) + list(extra_notes or []),
        "limitations": list(LIMITATIONS),
    }


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _score_color(value: int) -> str:
    if value >= 85:
        return "#b3261e"
    if value >= 70:
        return "#d9480f"
    if value >= 45:
        return "#b7791f"
    if value >= 20:
        return "#2f6f4f"
    return "#1f6f43"


def _render_finding(finding: dict[str, Any]) -> str:
    evidence = "".join(
        f'<li><code>{_e(item["artifact"])}</code>'
        + (f' <span class="lines">{_e(item["lines"])}</span>' if item.get("lines") else "")
        + f'<pre>{_e(item["quote"])}</pre></li>'
        for item in finding.get("evidence", [])
    )
    evidence_block = f'<ul class="evidence">{evidence}</ul>' if evidence else ""
    mitre = (
        '<p class="mitre">MITRE ATT&amp;CK Mobile: '
        + ", ".join(_e(technique) for technique in finding.get("mitre", []))
        + "</p>"
        if finding.get("mitre")
        else ""
    )
    return f"""
    <article class="finding sev-{_e(finding['severity'])}">
      <header>
        <span class="badge">{_e(finding['severity'])}</span>
        <span class="fid">{_e(finding['id'])}</span>
        <h3>{_e(finding['title'])}</h3>
      </header>
      <p class="what">{_e(finding['description'])}</p>
      <p class="why"><strong>Why it matters:</strong> {_e(finding['rationale'])}</p>
      {evidence_block}
      {mitre}
    </article>"""


def render_html(report: dict[str, Any]) -> str:
    apk = report["apk"]
    score = report["score"]
    verdict = report["verdict"]
    color = _score_color(score["value"])

    permissions = "".join(
        f"<li><code>{_e(permission)}</code></li>" for permission in apk.get("permissions", [])
    ) or "<li class='muted'>none requested</li>"

    components = "".join(
        "<tr>"
        f"<td>{_e(component['kind'])}</td>"
        f"<td><code>{_e(component['name'])}</code></td>"
        f"<td>{_e('yes' if component['exported'] else 'no' if component['exported'] is False else 'default')}</td>"
        f"<td>{_e(component['permission'] or '-')}</td>"
        "</tr>"
        for component in apk.get("components", [])[:80]
    )

    certs = "".join(
        f"<li><code>{_e(cert['sha256'][:32])}...</code> {_e(cert['subject'])}"
        + (" <span class='tag'>debug</span>" if cert["debug"] else "")
        + (" <span class='tag'>expired</span>" if cert["expired"] else "")
        + "</li>"
        for cert in apk.get("certs", [])
    ) or "<li class='muted'>not signed / unreadable</li>"

    findings_html = "".join(_render_finding(finding) for finding in report["findings"]) or (
        "<p class='muted'>No rule matched. That is not proof of safety.</p>"
    )

    combos_html = "".join(
        f"<li><strong>{_e(combo['id'])} - {_e(combo['title'])}</strong>"
        f"<p>{_e(combo['rationale'])}</p></li>"
        for combo in report["combos"]
    ) or "<li class='muted'>No combination rule fired.</li>"

    ranked_html = "".join(
        "<tr>"
        f"<td><code>{_e(item['name'])}</code></td>"
        f"<td>{item['score']}</td>"
        f"<td>{_e('; '.join(item['reasons']) or '-')}</td>"
        "</tr>"
        for item in report.get("ranked_classes", [])[:12]
    )
    ranked_block = (
        "<table><tr><th>Class</th><th>Rank</th><th>Why</th></tr>" + ranked_html + "</table>"
        if ranked_html
        else "<p class='muted'>No class scored above zero. Nothing stood out to read.</p>"
    )

    capabilities_html = "".join(
        f"<li>{_e(item['label'])} <span class='muted'>({item['findings']})</span></li>"
        for item in report["capabilities"]
    ) or "<li class='muted'>None observed</li>"

    warnings_html = "".join(f"<li>{_e(text)}</li>" for text in report["warnings"])
    limitations_html = "".join(f"<li>{_e(text)}</li>" for text in report["limitations"])

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ANBU report - {_e(apk['package'])}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 24px; font: 16px/1.55 -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #f7f7f5; color: #1c1c1a; }}
  main {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 4px; }}
  h2 {{ font-size: 1.05rem; margin: 32px 0 12px; text-transform: uppercase; letter-spacing: .06em;
        color: #56564f; }}
  h3 {{ font-size: 1rem; margin: 0; }}
  .scorecard {{ display: flex; gap: 20px; align-items: center; background: #fff; border: 1px solid #e3e3dd;
                border-radius: 14px; padding: 20px; }}
  .dial {{ width: 104px; height: 104px; border-radius: 50%; flex: 0 0 auto;
           background: conic-gradient({color} {score['value']}%, #e6e6df 0); display: grid; place-items: center; }}
  .dial span {{ width: 78px; height: 78px; border-radius: 50%; background: #fff; display: grid;
                place-items: center; font-size: 1.6rem; font-weight: 700; color: {color}; }}
  .band {{ font-weight: 700; color: {color}; margin: 0 0 4px; }}
  .advice {{ margin: 0; }}
  .meta {{ color: #56564f; font-size: .92rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e3e3dd;
           border-radius: 12px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #eceae4; font-size: .92rem;
            vertical-align: top; }}
  th {{ background: #f1f0ea; font-weight: 600; }}
  ul {{ padding-left: 20px; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .86rem; }}
  pre {{ margin: 6px 0 0; padding: 8px 10px; background: #f4f3ee; border-radius: 8px; overflow-x: auto;
         white-space: pre-wrap; word-break: break-word; }}
  .finding {{ background: #fff; border: 1px solid #e3e3dd; border-left: 5px solid #999; border-radius: 10px;
              padding: 14px 16px; margin-bottom: 12px; }}
  .finding header {{ display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }}
  .sev-critical {{ border-left-color: #b3261e; }}
  .sev-high {{ border-left-color: #d9480f; }}
  .sev-medium {{ border-left-color: #b7791f; }}
  .sev-low {{ border-left-color: #4a6fa5; }}
  .badge {{ text-transform: uppercase; font-size: .7rem; letter-spacing: .06em; font-weight: 700;
            background: #f1f0ea; border-radius: 999px; padding: 2px 8px; }}
  .fid {{ color: #77776f; font-size: .8rem; }}
  .what {{ margin: 8px 0 4px; }}
  .why {{ margin: 0; color: #3c3c37; }}
  .evidence {{ list-style: none; padding: 0; margin: 10px 0 0; }}
  .evidence li {{ margin-bottom: 8px; }}
  .lines, .muted {{ color: #77776f; }}
  .mitre {{ font-size: .85rem; color: #56564f; margin: 8px 0 0; }}
  .tag {{ background: #fde8e6; color: #b3261e; border-radius: 6px; padding: 1px 6px; font-size: .75rem; }}
  footer {{ margin: 32px 0 8px; color: #77776f; font-size: .85rem; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #14140f; color: #ecebe4; }}
    .scorecard, .finding, table {{ background: #1d1d18; border-color: #33332c; }}
    .dial span {{ background: #1d1d18; }}
    th {{ background: #26261f; }}
    th, td {{ border-color: #33332c; }}
    pre {{ background: #26261f; }}
    .why {{ color: #d6d5cc; }}
    .badge {{ background: #2a2a22; }}
  }}
</style>
</head>
<body>
<main>
  <h1>{_e(apk['label'] or apk['package'])}</h1>
  <p class="meta"><code>{_e(apk['package'])}</code> &middot; version {_e(apk['version_name'] or '?')}
     &middot; target SDK {_e(apk['target_sdk'] or '?')}</p>

  <section class="scorecard">
    <div class="dial"><span>{score['value']}</span></div>
    <div>
      <p class="band">{_e(verdict['headline'])}</p>
      <p class="advice">{_e(verdict['advice'])}</p>
      <p class="meta">Band: {_e(verdict['band'])} &middot; confidence: {_e(verdict['confidence'])}
         &middot; static coverage: {score['coverage']:.0%}
         {"&middot; <strong>inconclusive</strong>" if verdict['inconclusive'] else ""}</p>
    </div>
  </section>

  <h2>What can this app do?</h2>
  <ul>{capabilities_html}</ul>

  <h2>Findings ({len(report['findings'])})</h2>
  {findings_html}

  <h2>Combinations</h2>
  <ul>{combos_html}</ul>

  <h2>Classes worth reading</h2>
  {ranked_block}

  <h2>Identity</h2>
  <table>
    <tr><th>SHA-256</th><td><code>{_e(apk['sha256'])}</code></td></tr>
    <tr><th>Size</th><td>{apk['size']} bytes</td></tr>
    <tr><th>Min / target SDK</th><td>{_e(apk['min_sdk'] or '?')} / {_e(apk['target_sdk'] or '?')}</td></tr>
    <tr><th>DEX files</th><td>{apk['dex_count']} ({apk['class_count']} classes, {apk['method_count']} methods)</td></tr>
    <tr><th>Signing certificates</th><td><ul>{certs}</ul></td></tr>
  </table>

  <h2>Permissions</h2>
  <ul>{permissions}</ul>

  <h2>Components</h2>
  <table>
    <tr><th>Kind</th><th>Name</th><th>Exported</th><th>Permission</th></tr>
    {components}
  </table>

  <h2>Warnings and coverage</h2>
  <ul>{warnings_html}</ul>

  <h2>Limits of this analysis</h2>
  <ul>{limitations_html}</ul>

  <footer>ANBU {_e(report['tool']['version'])} - generated offline from static analysis.
  The APK was unpacked, never executed.</footer>
</main>
</body>
</html>
"""


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(report), encoding="utf-8")
    return out
