"""Rank classes by how suspicious their code looks, then slice the top ones.

Full decompilation is slow and mostly wasted. This module picks the handful of
classes worth reading (or sending to a model), and renders a compact slice of
each: class header, invoked methods and string constants.

The ranking is deliberately simple and explainable: weighted call patterns plus
class/method name keywords. It is a selection aid, not a verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

STRING_INSN = ("const-string", "const-string/jumbo")
QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
MAX_CALLS_IN_SLICE = 60
MAX_STRINGS_IN_SLICE = 40
MAX_SLICE_CHARS = 6000


@dataclass
class ClassSignals:
    name: str
    superclass: str = ""
    interfaces: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()
    method_names: tuple[str, ...] = ()
    native: bool = False


@dataclass
class RankedClass:
    name: str
    score: int
    reasons: list[str] = field(default_factory=list)
    artifact: str = "classes.dex"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "reasons": list(self.reasons),
            "artifact": self.artifact,
        }


def class_simple_name(name: str) -> str:
    """`Lcom/x/PayloadLoader;` -> `PayloadLoader`."""
    trimmed = name.strip()
    if trimmed.startswith("L"):
        trimmed = trimmed[1:]
    if trimmed.endswith(";"):
        trimmed = trimmed[:-1]
    return trimmed.rsplit("/", 1)[-1]


def name_segments(name: str) -> list[str]:
    """Split CamelCase/snake identifiers so `bottom` never matches `bot`."""
    return [
        part.lower()
        for part in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", name)
    ]


def _keywords_in(text: str, keywords: Iterable[str]) -> list[str]:
    segments = set(name_segments(text))
    return [keyword for keyword in keywords if keyword and keyword.lower() in segments]


def score_signals(
    signals: ClassSignals,
    weights: list[dict[str, Any]],
    keywords: list[str],
    keyword_weight: int = 3,
    keyword_cap: int = 9,
    framework_weight: int = 10,
) -> RankedClass:
    """Pure scoring step so the ranking policy is unit-testable."""
    score = 0
    reasons: list[str] = []

    joined_calls = "\n".join(signals.calls)
    for entry in weights:
        if entry["pattern"].lower() in joined_calls.lower():
            score += int(entry["weight"])
            reasons.append(entry["reason"])

    header = " ".join((signals.name, signals.superclass, *signals.interfaces))
    framework = _keywords_in(
        header, ("AccessibilityService", "NotificationListenerService", "DeviceAdminReceiver")
    )
    if framework:
        score += framework_weight
        reasons.append("implements a high-risk framework service")

    hits = _keywords_in(
        class_simple_name(signals.name) + " " + " ".join(signals.method_names), keywords
    )
    if hits:
        score += min(len(hits) * keyword_weight, keyword_cap)
        reasons.append("suspicious names: " + ", ".join(sorted(set(hits))[:4]))

    if signals.native:
        score += 2
        reasons.append("native methods")

    # Keep reasons stable and de-duplicated for reproducible reports.
    unique = list(dict.fromkeys(reasons))
    return RankedClass(name=signals.name, score=score, reasons=unique)


def _dex_name(index: int, archive_names: list[str]) -> str:
    if index < len(archive_names):
        return archive_names[index]
    return "classes.dex" if index == 0 else f"classes{index + 1}.dex"


def _signals_for(dex_class, dx) -> ClassSignals:
    calls: list[str] = []
    method_names: list[str] = []
    native = False
    for method in dex_class.get_methods():
        method_names.append(method.get_name())
        if "native" in (method.get_access_flags_string() or ""):
            native = True
        analysis = dx.get_method(method)
        if analysis is None:
            continue
        for _cls, called, _offset in analysis.get_xref_to():
            calls.append(f"{called.class_name}->{called.name}")
    return ClassSignals(
        name=dex_class.get_name(),
        superclass=dex_class.get_superclassname() or "",
        interfaces=tuple(str(i) for i in dex_class.get_interfaces()),
        calls=tuple(calls),
        method_names=tuple(method_names),
        native=native,
    )


def rank_classes(
    dexes: list,
    dx,
    weights: list[dict[str, Any]],
    keywords: list[str],
    archive_names: list[str] | None = None,
    limit: int = 25,
    ignore_prefixes: Iterable[str] = (),
) -> list[RankedClass]:
    archive_names = archive_names or []
    prefixes = tuple(ignore_prefixes)
    ranked: list[RankedClass] = []
    for index, dex in enumerate(dexes):
        artifact = _dex_name(index, archive_names)
        for dex_class in dex.get_classes():
            name = dex_class.get_name()
            if prefixes and name.startswith(prefixes):
                # Platform and library code is not what an analyst needs to read.
                continue
            scored = score_signals(_signals_for(dex_class, dx), weights, keywords)
            if scored.score <= 0:
                continue
            scored.artifact = artifact
            ranked.append(scored)
    ranked.sort(key=lambda item: (-item.score, item.name))
    return ranked[:limit]


def _method_line(analysis) -> str:
    flags = analysis.get_access_flags_string() or ""
    return f"  {flags} {analysis.name}{analysis.descriptor}".strip()


def _quoted_strings(analysis) -> list[str]:
    found: list[str] = []
    for block in analysis.get_basic_blocks():
        for instruction in block.get_instructions():
            if instruction.get_name() not in STRING_INSN:
                continue
            match = QUOTED.search(instruction.get_output())
            if match:
                found.append(match.group(1))
    return found


def build_slice(
    dex_class,
    dx,
    max_calls: int = MAX_CALLS_IN_SLICE,
    max_strings: int = MAX_STRINGS_IN_SLICE,
) -> str:
    """Render one class as a compact, prompt-safe text slice.

    Everything from the APK is JSON-escaped, so an app cannot break out of a
    string literal to inject instructions into a model prompt.
    """
    lines = [f"class {dex_class.get_name()} extends {dex_class.get_superclassname() or '?'}"]
    interfaces = [str(i) for i in dex_class.get_interfaces()]
    if interfaces:
        lines.append("implements " + ", ".join(interfaces))

    calls: list[str] = []
    strings: list[str] = []
    for method in dex_class.get_methods():
        analysis = dx.get_method(method)
        if analysis is None:
            continue
        lines.append(_method_line(analysis))
        for _cls, called, _offset in analysis.get_xref_to():
            ref = f"{called.class_name}->{called.name}"
            if ref not in calls:
                calls.append(ref)
        for text in _quoted_strings(analysis):
            if text not in strings:
                strings.append(text)

    if calls:
        lines.append("calls:")
        lines.extend(f"  {json.dumps(ref)}" for ref in calls[:max_calls])
        if len(calls) > max_calls:
            lines.append(f"  ... {len(calls) - max_calls} more")
    if strings:
        lines.append("strings:")
        lines.extend(f"  {json.dumps(text[:200])}" for text in strings[:max_strings])
        if len(strings) > max_strings:
            lines.append(f"  ... {len(strings) - max_strings} more")

    text = "\n".join(lines)
    if len(text) > MAX_SLICE_CHARS:
        text = text[:MAX_SLICE_CHARS] + "\n... slice truncated"
    return text


def slices_for(dexes: list, dx, ranked: list[RankedClass]) -> dict[str, str]:
    """Build slices only for the ranked classes, keyed by class name."""
    wanted = {item.name for item in ranked}
    slices: dict[str, str] = {}
    for dex in dexes:
        for dex_class in dex.get_classes():
            name = dex_class.get_name()
            if name in wanted and name not in slices:
                slices[name] = build_slice(dex_class, dx)
    return slices
