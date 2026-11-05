"""Evidence verification for model-produced findings.

A quote is accepted only when it appears verbatim in a fact extracted from the
APK, and the artifact it names must be the artifact that fact came from. Model
findings with no verified evidence are dropped rather than downgraded, because
this project would rather miss a behaviour than invent one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from anbu.models import SEVERITIES, ApkInfo, Evidence, Finding

CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")
MITRE_RE = re.compile(r"^T\d{4}$")
MAX_FINDINGS = 6
MAX_PER_CATEGORY = 3
MAX_QUOTE_CHARS = 300


@dataclass
class VerificationResult:
    findings: list[Finding] = field(default_factory=list)
    dropped: int = 0
    notes: list[str] = field(default_factory=list)


def _norm(text: object) -> str:
    return " ".join(str(text).split())


def fact_index(info: ApkInfo) -> dict[str, str]:
    """Map every quotable fact to the artifact that contains it."""
    dex = info.dex_names[0] if info.dex_names else "classes.dex"
    index: dict[str, str] = {}

    for permission in info.permissions:
        index.setdefault(_norm(permission), "AndroidManifest.xml")
    for action in info.intent_actions:
        index.setdefault(_norm(action), "AndroidManifest.xml")
    for component in info.components:
        index.setdefault(_norm(component.name), "AndroidManifest.xml")
    for name, value in info.flags.items():
        if value is not None:
            index.setdefault(_norm(f'android:{name}="{value}"'), "AndroidManifest.xml")
    for cert in info.certs:
        index.setdefault(_norm(cert.subject), "META-INF/")
    for ref in info.api_refs:
        index.setdefault(_norm(ref), info.artifact_for(ref, dex))
    for text in info.strings:
        index.setdefault(_norm(text), info.artifact_for(text, dex))
    for url in info.urls:
        index.setdefault(_norm(url), info.artifact_for(url, dex))
    for asset in info.assets:
        index.setdefault(_norm(asset), asset)
    for lib in info.native_libs:
        index.setdefault(_norm(lib), lib)
    return index


def _parse(raw: str | dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    if isinstance(raw, dict):
        return raw, None
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None, "model reply was not valid JSON"
    if not isinstance(parsed, dict):
        return None, "model reply was not a JSON object"
    return parsed, None


def _clean_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text or len(text) > limit:
        return None
    return text


def _verify_evidence(
    items: object, index: dict[str, str]
) -> tuple[list[Evidence], int]:
    if not isinstance(items, list):
        return [], 0
    verified: list[Evidence] = []
    rejected = 0
    for item in items:
        if not isinstance(item, dict):
            rejected += 1
            continue
        quote = _clean_text(item.get("quote"), MAX_QUOTE_CHARS)
        artifact = _clean_text(item.get("artifact"), 200)
        if quote is None or artifact is None:
            rejected += 1
            continue
        expected = index.get(_norm(quote))
        if expected is None or expected != artifact:
            rejected += 1
            continue
        verified.append(Evidence(artifact=expected, quote=quote))
    return verified, rejected


def verify_response(raw: str | dict[str, Any], info: ApkInfo) -> VerificationResult:
    payload, problem = _parse(raw)
    if payload is None:
        return VerificationResult(notes=[problem or "model reply could not be read"])

    index = fact_index(info)
    result = VerificationResult()
    counts: dict[str, int] = {}
    for item in payload.get("findings", []):
        if len(result.findings) >= MAX_FINDINGS:
            result.dropped += 1
            continue
        if not isinstance(item, dict):
            result.dropped += 1
            continue

        severity = str(item.get("severity", "")).lower()
        category = str(item.get("category", "")).strip()
        title = _clean_text(item.get("title"), 200)
        description = _clean_text(item.get("description"), 800)
        rationale = _clean_text(item.get("rationale"), 800)
        if (
            severity not in SEVERITIES
            or not CATEGORY_RE.match(category)
            or title is None
            or description is None
            or rationale is None
        ):
            result.dropped += 1
            continue
        if counts.get(category, 0) >= MAX_PER_CATEGORY:
            result.dropped += 1
            result.notes.append(f"category cap reached for {category}")
            continue

        evidence, rejected = _verify_evidence(item.get("evidence"), index)
        if not evidence:
            result.dropped += 1
            result.notes.append(f"dropped unverified finding: {title}")
            continue
        if rejected:
            result.notes.append(f"{title}: discarded {rejected} unverifiable quote(s)")

        mitre = [
            str(technique)
            for technique in item.get("mitre", [])
            if isinstance(technique, str) and MITRE_RE.match(technique)
        ]
        try:
            confidence = float(item.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        counts[category] = counts.get(category, 0) + 1
        result.findings.append(
            Finding(
                id=f"F-{len(result.findings) + 1:03d}",
                title=title,
                severity=severity,
                category=category,
                description=description,
                rationale=rationale,
                evidence=evidence,
                mitre=mitre,
                confidence=confidence,
                source="llm",
                verified=True,
            )
        )
    return result
