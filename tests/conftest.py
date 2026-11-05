from __future__ import annotations

from pathlib import Path

import pytest

from anbu.models import ApkInfo, CertInfo, Component

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
BENIGN_APK = SAMPLES / "benign-dicer.apk"

requires_sample = pytest.mark.skipif(
    not BENIGN_APK.exists(),
    reason="sample APKs are git-ignored; run the fixture test on a machine that has one",
)


def make_info(**overrides) -> ApkInfo:
    defaults = dict(
        path="sample.apk",
        sha256="0" * 64,
        size=1024,
        package="com.example.app",
        label="Example",
        version_name="1.0",
        version_code="1",
        min_sdk=24,
        target_sdk=34,
        dex_names=["classes.dex"],
        dex_count=1,
        coverage=1.0,
    )
    defaults.update(overrides)
    return ApkInfo(**defaults)


def make_component(name: str, kind: str = "service", exported: bool | None = False, permission=None):
    return Component(name=name, kind=kind, exported=exported, permission=permission)


def make_cert(**overrides) -> CertInfo:
    defaults = dict(
        subject="CN=Release, O=Example",
        issuer="CN=Release, O=Example",
        sha256="ab" * 32,
        not_before="2024-01-01T00:00:00+00:00",
        not_after="2034-01-01T00:00:00+00:00",
        expired=False,
        debug=False,
    )
    defaults.update(overrides)
    return CertInfo(**defaults)
