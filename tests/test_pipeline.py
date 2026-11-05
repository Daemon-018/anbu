from __future__ import annotations

from anbu.analyze import analyze
from anbu.cli import main
from anbu.ingest import IngestError, validate_apk
from tests.conftest import BENIGN_APK, requires_sample


def test_ingest_rejects_non_zip(tmp_path):
    fake = tmp_path / "fake.apk"
    fake.write_bytes(b"not a zip")
    try:
        validate_apk(fake)
    except IngestError as exc:
        assert "ZIP" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("non-archive was accepted")


def test_ingest_rejects_missing_file(tmp_path):
    try:
        validate_apk(tmp_path / "missing.apk")
    except IngestError as exc:
        assert "not found" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("missing file was accepted")


@requires_sample
def test_benign_sample_scores_low_and_quotes_evidence():
    analysis = analyze(BENIGN_APK)
    assert analysis.info.package == "org.secuso.privacyfriendlydicer"
    assert analysis.info.class_count > 0
    assert analysis.info.dex_count >= 1
    assert analysis.info.coverage == 1.0
    assert analysis.score.band in {"likely_benign", "low"}
    assert not analysis.score.inconclusive
    assert "android.permission.VIBRATE" in analysis.info.permissions
    for finding in analysis.findings:
        assert finding.evidence, finding.id


@requires_sample
def test_cli_writes_both_reports(tmp_path):
    out = tmp_path / "reports"
    status = main(["scan", str(BENIGN_APK), "--out", str(out)])
    assert status == 0
    assert (out / "benign-dicer.json").exists()
    assert (out / "benign-dicer.html").exists()
