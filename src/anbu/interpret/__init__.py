"""Optional model interpretation of ranked code slices.

The model adds findings; the deterministic scorer still owns the number. Every
finding must pass evidence verification or it is dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from anbu.interpret.client import LlmClient, LlmConfig, LlmError
from anbu.interpret.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_payload, render_prompt
from anbu.interpret.verify import VerificationResult, fact_index, verify_response
from anbu.models import ApkInfo, Finding

__all__ = [
    "Interpretation",
    "LlmClient",
    "LlmConfig",
    "LlmError",
    "PROMPT_VERSION",
    "client_from_env",
    "fact_index",
    "interpret",
    "verify_response",
]


@dataclass
class Interpretation:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    used_model: bool = False


def client_from_env() -> LlmClient | None:
    config = LlmConfig.from_env()
    return LlmClient(config) if config else None


def interpret(
    info: ApkInfo,
    slices: dict[str, str],
    rule_findings: list[Finding] | None = None,
    client: LlmClient | None = None,
) -> Interpretation:
    if client is None:
        return Interpretation()
    if not slices:
        return Interpretation(notes=["model pass skipped: no class slice was suspicious"])

    payload = build_payload(info, slices, rule_findings or [])
    prompt = render_prompt(payload)
    try:
        raw = client.complete(SYSTEM_PROMPT, prompt)
    except LlmError as exc:
        return Interpretation(notes=[f"model pass skipped: {exc}"])

    result: VerificationResult = verify_response(raw, info)
    notes = [
        f"model pass: {len(result.findings)} verified finding(s), "
        f"{result.dropped} dropped by the evidence gate"
    ]
    notes.extend(result.notes)
    return Interpretation(findings=result.findings, notes=notes, used_model=True)
