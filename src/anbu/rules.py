"""Evaluate the declarative rule and combination packs against an APK model.

The engine is deliberately small: packages own the logic, JSON owns the policy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from anbu.models import ApkInfo, Combination, Evidence, Finding

RULES_PATH = Path(__file__).with_name("data") / "rules.json"


class RuleError(ValueError):
    """The rule pack is malformed."""


def load_pack(path: Path | None = None) -> dict[str, Any]:
    with (path or RULES_PATH).open(encoding="utf-8") as handle:
        return json.load(handle)


def _api_matches(info: ApkInfo, needle: str) -> list[str]:
    lowered = needle.lower()
    return [ref for ref in info.api_refs if lowered in ref.lower()]


def _string_matches(info: ApkInfo, needle: str) -> list[str]:
    lowered = needle.lower()
    return [text for text in info.strings if lowered in text.lower()]


def _regex_matches(values: list[str], pattern: str) -> list[str]:
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise RuleError(f"invalid regex in rule pack: {pattern!r} ({exc})") from exc
    return [value for value in values if compiled.search(value)]


def _api_evidence(info: ApkInfo, refs: list[str]) -> list[Evidence]:
    return [
        Evidence(artifact=info.artifact_for(ref, info.dex_names[0] if info.dex_names else "classes.dex"), quote=ref)
        for ref in refs[:3]
    ]


def _string_evidence(info: ApkInfo, texts: list[str]) -> list[Evidence]:
    return [
        Evidence(
            artifact=info.artifact_for(
                text, info.dex_names[0] if info.dex_names else "classes.dex"
            ),
            quote=text[:200],
        )
        for text in texts[:3]
    ]


def _permission_evidence(info: ApkInfo, permissions: list[str]) -> list[Evidence]:
    return [
        Evidence(artifact=info.artifact_for(permission, "AndroidManifest.xml"), quote=permission)
        for permission in permissions[:4]
    ]


def _atom(info: ApkInfo, kind: str, value: Any) -> list[Evidence] | None:
    """Return evidence when the atom matches, else ``None``."""
    if kind == "permission":
        return _permission_evidence(info, [value]) if value in info.permissions else None

    if kind == "permission_any":
        hits = [permission for permission in value if permission in info.permissions]
        return _permission_evidence(info, hits) if hits else None

    if kind == "api":
        hits = _api_matches(info, value)
        return _api_evidence(info, hits) if hits else None

    if kind == "api_any":
        hits: list[str] = []
        for needle in value:
            hits.extend(_api_matches(info, needle))
        seen = list(dict.fromkeys(hits))
        return _api_evidence(info, seen) if seen else None

    if kind == "string":
        hits = _string_matches(info, value)
        return _string_evidence(info, hits) if hits else None

    if kind == "string_any":
        hits: list[str] = []
        for needle in value:
            hits.extend(_string_matches(info, needle))
        seen = list(dict.fromkeys(hits))
        return _string_evidence(info, seen) if seen else None

    if kind == "string_regex":
        hits = _regex_matches(info.strings, value)
        return _string_evidence(info, hits) if hits else None

    if kind == "url_regex":
        hits = _regex_matches(info.urls, value)
        if not hits:
            return None
        return [
            Evidence(
                artifact=info.artifact_for(url, info.dex_names[0] if info.dex_names else "classes.dex"),
                quote=url,
            )
            for url in hits[:3]
        ]

    if kind == "flag":
        name = value["name"]
        expected = str(value["value"]).lower()
        actual = info.flags.get(name)
        if actual is None or actual.lower() != expected:
            return None
        return [Evidence("AndroidManifest.xml", f'android:{name}="{actual}"')]

    if kind == "asset":
        hits = _regex_matches(info.assets, value)
        return [Evidence(asset, asset) for asset in hits[:3]] if hits else None

    if kind == "native_lib":
        hits = _regex_matches(info.native_libs, value)
        return [Evidence(lib, lib) for lib in hits[:3]] if hits else None

    if kind == "high_entropy_asset":
        if not value or not info.high_entropy_assets:
            return None
        return [Evidence(asset, asset) for asset in info.high_entropy_assets[:3]]

    if kind == "intent_action":
        if value not in info.intent_actions:
            return None
        return [Evidence("AndroidManifest.xml", value)]

    if kind == "component_name_contains":
        kind_filter = value.get("kind")
        text = value["text"]
        hits = [
            component
            for component in info.components
            if (kind_filter is None or component.kind == kind_filter) and text in component.name
        ]
        return [
            Evidence("AndroidManifest.xml", component.name) for component in hits[:3]
        ] if hits else None

    if kind == "exported_unprotected":
        exposed = [
            component
            for component in info.components
            if component.exported is True and not component.permission
        ]
        if len(exposed) < int(value):
            return None
        return [
            Evidence("AndroidManifest.xml", f"{component.kind}: {component.name}")
            for component in exposed[:3]
        ]

    if kind == "cert_debug":
        hits = [cert for cert in info.certs if cert.debug]
        return [Evidence("META-INF/", cert.subject) for cert in hits[:2]] if hits else None

    if kind == "cert_expired":
        hits = [cert for cert in info.certs if cert.expired]
        return [Evidence("META-INF/", cert.subject) for cert in hits[:2]] if hits else None

    if kind == "packer":
        if not info.packer_hints:
            return None
        evidence: list[Evidence] = []
        for packer in info.packer_hints[:2]:
            marker = info.packer_evidence.get(packer)
            if marker is None:
                continue
            evidence.append(
                Evidence(
                    artifact=info.artifact_for(
                        marker, info.dex_names[0] if info.dex_names else "classes.dex"
                    ),
                    quote=marker,
                )
            )
        return evidence or None

    raise RuleError(f"unknown condition type: {kind!r}")


def _match(info: ApkInfo, condition: dict[str, Any]) -> list[Evidence] | None:
    """Evaluate one condition tree, returning merged evidence or ``None``."""
    if not isinstance(condition, dict) or len(condition) != 1:
        raise RuleError(f"condition must be a single-key object: {condition!r}")
    (kind, value), = condition.items()

    if kind == "all":
        evidence: list[Evidence] = []
        for item in value:
            matched = _match(info, item)
            if matched is None:
                return None
            evidence.extend(matched)
        return evidence

    if kind == "any":
        evidence = []
        matched_any = False
        for item in value:
            matched = _match(info, item)
            if matched is not None:
                matched_any = True
                evidence.extend(matched)
        return evidence if matched_any else None

    if kind == "not":
        return [] if _match(info, value) is None else None

    return _atom(info, kind, value)


def _required(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    raise RuleError(f"rule requires a condition object, got {value!r}")


def run_rules(info: ApkInfo, pack: dict[str, Any] | None = None) -> list[Finding]:
    pack = pack or load_pack()
    findings: list[Finding] = []
    for raw in pack.get("rules", []):
        evidence = _match(info, _required(raw.get("requires")))
        if evidence is None:
            continue
        findings.append(
            Finding(
                id=raw["id"],
                title=raw["title"],
                severity=raw["severity"],
                category=raw["category"],
                description=raw["description"],
                rationale=raw["rationale"],
                evidence=evidence,
                mitre=list(raw.get("mitre", [])),
                confidence=float(raw.get("confidence", 0.9)),
                source="rule",
                verified=True,
            )
        )
    return findings


def run_combos(findings: list[Finding], pack: dict[str, Any] | None = None) -> list[Combination]:
    pack = pack or load_pack()
    present = {finding.id for finding in findings}
    triggered: list[Combination] = []
    for raw in pack.get("combos", []):
        if set(raw["finding_ids"]).issubset(present):
            triggered.append(
                Combination(
                    id=raw["id"],
                    title=raw["title"],
                    rationale=raw["rationale"],
                    finding_ids=list(raw["finding_ids"]),
                )
            )
    return triggered
