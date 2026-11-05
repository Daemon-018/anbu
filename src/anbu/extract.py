"""Extract the facts the rule engine needs from an APK.

Everything here reads the archive; nothing is executed. androguard is used for
the binary manifest, certificates and DEX, while the raw ZIP is read for assets
so entropy checks do not depend on a third party.
"""

from __future__ import annotations

import json
import math
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from anbu.ingest import IngestResult
from anbu.models import ApkInfo, CertInfo, Component

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SIGNALS_PATH = Path(__file__).with_name("data") / "signals.json"

URL_RE = re.compile(r"https?://[^\s\"'<>\\]{4,200}", re.IGNORECASE)
# XML/SOAP namespaces look like URLs to a regex but are identifiers, not endpoints.
SCHEMA_HOSTS = {
    "schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
    "www.xmlpull.org",
    "ns.adobe.com",
    "schemas.xmlsoap.org",
    "purl.org",
    "json-schema.org",
}
MAX_STRINGS = 40_000
MAX_URLS = 200
HIGH_ENTROPY_BITS = 7.2
MAX_ENTROPY_ASSET_BYTES = 4 * 1024 * 1024
MAX_ENTROPY_ASSETS = 40

COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


@dataclass
class ApkArtifacts:
    """Extracted model plus the androguard objects needed by the ranker."""

    info: ApkInfo
    apk: Any
    dexes: list
    dx: Any


def load_signals() -> dict:
    with SIGNALS_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _bool_attr(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def _certificates(apk) -> tuple[list[CertInfo], list[str]]:
    warnings: list[str] = []
    certs: list[CertInfo] = []
    try:
        raw_certs = apk.get_certificates()
    except Exception as exc:  # noqa: BLE001 - a broken cert must not stop the scan
        return [], [f"certificate parsing failed: {type(exc).__name__}"]

    now = datetime.now(timezone.utc)
    for cert in raw_certs:
        try:
            subject = cert.subject.human_friendly
            issuer = cert.issuer.human_friendly
            fingerprint = cert.sha256.hex()
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            expired = bool(not_after and not_after < now)
            debug = "CN=Android Debug" in subject or "Android Debug" in issuer
            certs.append(
                CertInfo(
                    subject=subject,
                    issuer=issuer,
                    sha256=fingerprint,
                    not_before=not_before.isoformat() if not_before else None,
                    not_after=not_after.isoformat() if not_after else None,
                    expired=expired,
                    debug=debug,
                )
            )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"certificate could not be read: {type(exc).__name__}")
    if not certs:
        warnings.append("APK is not signed or the signature could not be parsed")
    return certs, warnings


def _components(root, warnings: list[str]) -> tuple[list[Component], list[str]]:
    application = root.find("application")
    if application is None:
        warnings.append("manifest has no <application> element")
        return [], []

    components: list[Component] = []
    intent_actions: list[str] = []
    for child in application:
        tag = child.tag if isinstance(child.tag, str) else ""
        kind = COMPONENT_TAGS.get(tag)
        if kind is None:
            continue
        name = _text(child.get(ANDROID_NS + "name"))
        if name is None:
            continue
        components.append(
            Component(
                name=name,
                kind=kind,
                exported=_bool_attr(child.get(ANDROID_NS + "exported")),
                permission=_text(child.get(ANDROID_NS + "permission")),
            )
        )
        for intent_filter in child.findall("intent-filter"):
            for action in intent_filter.findall("action"):
                action_name = _text(action.get(ANDROID_NS + "name"))
                if action_name and action_name not in intent_actions:
                    intent_actions.append(action_name)
    return components, intent_actions


def _flags(root) -> dict[str, str | None]:
    application = root.find("application")
    wanted = (
        "debuggable",
        "allowBackup",
        "usesCleartextTraffic",
        "testOnly",
        "extractNativeLibs",
        "networkSecurityConfig",
        "requestLegacyExternalStorage",
    )
    flags: dict[str, str | None] = {}
    if application is None:
        return flags
    for name in wanted:
        flags[name] = _text(application.get(ANDROID_NS + name))
    return flags


def _dex_facts(
    dexes, signals: dict, archive_dex_names: list[str] | None = None
) -> tuple[dict, list[str], dict[str, str], list[str], list[str]]:
    """Walk every DEX once and collect the cheap, high-signal facts."""
    sink_substrings = [s.lower() for s in signals.get("sink_substrings", [])]
    strings: dict[str, str] = {}  # dedupe, remember first dex that carries it
    api_refs: set[str] = set()
    sources: dict[str, str] = {}
    class_count = 0
    method_count = 0
    dex_names: list[str] = []

    archive_names = archive_dex_names or []
    for index, dex in enumerate(dexes):
        if index < len(archive_names):
            name = archive_names[index]
        else:
            name = "classes.dex" if index == 0 else f"classes{index + 1}.dex"
        dex_names.append(name)
        classes = dex.get_classes()
        class_count += len(classes)
        for dex_class in classes:
            for method in dex_class.get_methods():
                method_count += 1
                ref = f"{method.get_class_name()}->{method.get_name()}"
                lowered = ref.lower()
                if any(sink in lowered for sink in sink_substrings):
                    if ref not in sources:
                        api_refs.add(ref)
                        sources[ref] = name
        for string in dex.get_strings():
            if len(strings) >= MAX_STRINGS:
                break
            if len(string) < 3 or len(string) > 500:
                continue
            if string not in strings:
                strings[string] = name
                sources.setdefault(string, name)

    return (
        {
            "class_count": class_count,
            "method_count": method_count,
            "string_count": len(strings),
            "dex_names": dex_names,
        },
        list(api_refs),
        sources,
        list(strings),
        [],
    )


def _urls(strings: list[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for text in strings:
        for match in URL_RE.findall(text):
            url = match.rstrip(".,;:)")
            host = urlparse(url).hostname or ""
            if host in SCHEMA_HOSTS:
                continue
            if url and url not in seen:
                seen.add(url)
                found.append(url)
                if len(found) >= MAX_URLS:
                    return found
    return found


def _packer_hints(
    signals: dict, pairs: list[tuple[str, str]], sources: dict[str, str]
) -> tuple[list[str], dict[str, str]]:
    """Return (packer names, packer -> matched marker) and record marker artifacts."""
    hints: list[str] = []
    evidence: dict[str, str] = {}
    for packer, markers in signals.get("packers", {}).items():
        for marker in markers:
            lowered = marker.lower()
            hit = next(
                ((text, artifact) for text, artifact in pairs if lowered in text.lower()),
                None,
            )
            if hit is None:
                continue
            text, artifact = hit
            hints.append(packer)
            evidence[packer] = marker
            sources.setdefault(marker, artifact)
            break
    return hints, evidence


def _suspicious_assets(
    apk_path: Path, ingest: IngestResult, signals: dict
) -> tuple[list[str], list[str]]:
    patterns = [re.compile(p) for p in signals.get("suspicious_asset_patterns", [])]
    media = [re.compile(p) for p in signals.get("media_asset_patterns", [])]
    suspicious: list[str] = []
    high_entropy: list[str] = []
    candidates = ingest.assets[:MAX_ENTROPY_ASSETS]
    try:
        with zipfile.ZipFile(apk_path) as archive:
            for name in candidates:
                if any(p.search(name) for p in patterns) and not any(p.search(name) for p in media):
                    suspicious.append(name)
                try:
                    info = archive.getinfo(name)
                except KeyError:
                    continue
                if info.file_size > MAX_ENTROPY_ASSET_BYTES or info.file_size < 4096:
                    continue
                if any(p.search(name) for p in media):
                    continue
                with archive.open(info) as handle:
                    payload = handle.read(MAX_ENTROPY_ASSET_BYTES)
                if _shannon_entropy(payload) >= HIGH_ENTROPY_BITS:
                    high_entropy.append(name)
    except (OSError, zipfile.BadZipFile):
        pass
    return suspicious, high_entropy


def extract_apk(ingest: IngestResult, signals: dict | None = None) -> ApkInfo:
    """Parse the APK into :class:`ApkInfo` (thin wrapper over load_artifacts)."""
    return load_artifacts(ingest, signals).info


def load_artifacts(
    ingest: IngestResult, signals: dict | None = None
) -> ApkArtifacts:
    """Parse the APK once and keep the androguard objects for the ranker."""
    signals = signals or load_signals()
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - logging setup is best effort
        pass

    from androguard.misc import AnalyzeAPK

    apk, dexes, dx = AnalyzeAPK(str(ingest.path))
    warnings: list[str] = []

    root = apk.get_android_manifest_xml()
    components, intent_actions = _components(root, warnings)
    certs, cert_warnings = _certificates(apk)
    warnings.extend(cert_warnings)

    permissions = sorted({p for p in apk.get_permissions() if p})
    dex_facts, api_refs, sources, strings, dex_warnings = _dex_facts(
        dexes, signals, ingest.dex_names
    )
    warnings.extend(dex_warnings)

    for permission in permissions:
        sources.setdefault(permission, "AndroidManifest.xml")

    suspicious_assets, high_entropy = _suspicious_assets(ingest.path, ingest, signals)
    pairs = [(lib, lib) for lib in ingest.native_libs]
    pairs += [(asset, asset) for asset in suspicious_assets]
    pairs += list(sources.items())
    packers, packer_evidence = _packer_hints(signals, pairs, sources)

    unprotected = sum(
        1 for c in components if c.exported is True and not c.permission
    )
    coverage = 1.0 if dexes else 0.0
    if packers:
        # Packed DEX hides the real code from static analysis; say so.
        coverage = min(coverage, 0.3)
    warnings.extend(
        f"packer signature detected: {packer} (code may be hidden)" for packer in packers
    )

    info = ApkInfo(
        path=str(ingest.path),
        sha256=ingest.sha256,
        size=ingest.size,
        package=_text(apk.get_package()) or "",
        label=_text(apk.get_app_name()) or "",
        version_name=_text(apk.get_androidversion_name()),
        version_code=_text(apk.get_androidversion_code()),
        min_sdk=_as_int(apk.get_min_sdk_version()),
        target_sdk=_as_int(apk.get_target_sdk_version()),
        permissions=permissions,
        components=components,
        intent_actions=intent_actions,
        flags=_flags(root),
        certs=certs,
        dex_names=dex_facts["dex_names"] or ingest.dex_names,
        dex_count=len(dexes),
        class_count=dex_facts["class_count"],
        method_count=dex_facts["method_count"],
        string_count=dex_facts["string_count"],
        api_refs=sorted(api_refs),
        strings=strings,
        urls=_urls(strings),
        assets=ingest.assets,
        native_libs=ingest.native_libs,
        packer_hints=packers,
        high_entropy_assets=high_entropy + suspicious_assets,
        unprotected_exported=unprotected,
        coverage=coverage,
        warnings=warnings,
        sources=sources,
        packer_evidence=packer_evidence,
    )
    return ApkArtifacts(info=info, apk=apk, dexes=dexes, dx=dx)


def _as_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
