"""Core data model for extraction, rules, scoring and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {name: index for index, name in enumerate(reversed(SEVERITIES))}
BANDS = ("likely_benign", "low", "suspicious", "high", "critical")
BAND_RANK = {name: index for index, name in enumerate(BANDS)}


@dataclass
class Evidence:
    artifact: str
    quote: str
    lines: str | None = None


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    rationale: str
    evidence: list[Evidence] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    confidence: float = 0.8
    source: str = "rule"
    verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "rationale": self.rationale,
            "evidence": [
                {"artifact": e.artifact, "quote": e.quote, "lines": e.lines}
                for e in self.evidence
            ],
            "mitre": list(self.mitre),
            "confidence": self.confidence,
            "source": self.source,
            "verified": self.verified,
        }


@dataclass
class Combination:
    id: str
    title: str
    rationale: str
    finding_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "rationale": self.rationale,
            "finding_ids": list(self.finding_ids),
        }


@dataclass
class CertInfo:
    subject: str
    issuer: str
    sha256: str
    not_before: str | None
    not_after: str | None
    expired: bool
    debug: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "sha256": self.sha256,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "expired": self.expired,
            "debug": self.debug,
        }


@dataclass
class Component:
    name: str
    kind: str
    exported: bool | None
    permission: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "exported": self.exported,
            "permission": self.permission,
        }


@dataclass
class ApkInfo:
    path: str
    sha256: str
    size: int
    package: str
    label: str
    version_name: str | None
    version_code: str | None
    min_sdk: int | None
    target_sdk: int | None
    permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    intent_actions: list[str] = field(default_factory=list)
    flags: dict[str, str | None] = field(default_factory=dict)
    certs: list[CertInfo] = field(default_factory=list)
    dex_names: list[str] = field(default_factory=list)
    dex_count: int = 0
    class_count: int = 0
    method_count: int = 0
    string_count: int = 0
    api_refs: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    packer_hints: list[str] = field(default_factory=list)
    high_entropy_assets: list[str] = field(default_factory=list)
    unprotected_exported: int = 0
    coverage: float = 0.0
    warnings: list[str] = field(default_factory=list)
    # quote -> archive entry that contains it; used to attribute evidence.
    # Internal plumbing, deliberately not serialised into reports.
    sources: dict[str, str] = field(default_factory=dict)
    # packer name -> the marker string that matched, so the finding can quote it.
    # Internal plumbing, deliberately not serialised into reports.
    packer_evidence: dict[str, str] = field(default_factory=dict)

    def artifact_for(self, quote: str, default: str = "AndroidManifest.xml") -> str:
        return self.sources.get(quote, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "package": self.package,
            "label": self.label,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "permissions": list(self.permissions),
            "components": [c.to_dict() for c in self.components],
            "intent_actions": list(self.intent_actions),
            "flags": dict(self.flags),
            "certs": [c.to_dict() for c in self.certs],
            "dex_names": list(self.dex_names),
            "dex_count": self.dex_count,
            "class_count": self.class_count,
            "method_count": self.method_count,
            "string_count": self.string_count,
            "api_refs": list(self.api_refs),
            "strings": list(self.strings),
            "urls": list(self.urls),
            "assets": list(self.assets),
            "native_libs": list(self.native_libs),
            "packer_hints": list(self.packer_hints),
            "high_entropy_assets": list(self.high_entropy_assets),
            "unprotected_exported": self.unprotected_exported,
            "coverage": self.coverage,
            "warnings": list(self.warnings),
        }


@dataclass
class ScoreResult:
    value: int
    band: str
    confidence: str
    coverage: float
    inconclusive: bool
    base_points: int
    saturated: float
    combo_bonus: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "band": self.band,
            "confidence": self.confidence,
            "coverage": self.coverage,
            "inconclusive": self.inconclusive,
            "base_points": self.base_points,
            "saturated": round(self.saturated, 1),
            "combo_bonus": self.combo_bonus,
            "notes": list(self.notes),
        }
