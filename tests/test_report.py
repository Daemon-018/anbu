from __future__ import annotations

import json

from anbu.models import Combination, Evidence, Finding
from anbu.report import build_report, render_html, write_html, write_json
from anbu.score import score
from tests.conftest import make_cert, make_component, make_info


def sample_findings():
    return [
        Finding(
            id="PERM-01",
            title="Reads incoming SMS and has internet access",
            severity="high",
            category="sms_interception",
            description="The app can read text messages.",
            rationale="OTPs arrive by SMS.",
            evidence=[
                Evidence("AndroidManifest.xml", "android.permission.RECEIVE_SMS"),
                Evidence("classes.dex", "Landroid/telephony/SmsManager;->sendTextMessage", "112-140"),
            ],
            mitre=["T1412"],
            confidence=0.9,
        )
    ]


def sample_report():
    info = make_info(
        permissions=["android.permission.RECEIVE_SMS", "android.permission.INTERNET"],
        components=[make_component("com.example.Receiver", kind="receiver", exported=True)],
        certs=[make_cert()],
    )
    findings = sample_findings()
    combos = [Combination("OTP-STEALER", "OTP interception", "Reads SMS and listens.", ["PERM-01"])]
    return build_report(info, findings, combos, score(info, findings, combos))


def test_json_report_has_every_contract_field():
    report = sample_report()
    assert report["tool"]["name"] == "anbu"
    for key in ("apk", "score", "verdict", "capabilities", "findings", "combos", "warnings", "limitations"):
        assert key in report
    finding = report["findings"][0]
    assert finding["evidence"][0]["artifact"] == "AndroidManifest.xml"
    assert report["verdict"]["band"] == report["score"]["band"]
    # internal plumbing must not leak into the report
    assert "sources" not in report["apk"]
    assert "packer_evidence" not in report["apk"]


def test_html_is_self_contained():
    html = render_html(sample_report())
    assert html.startswith("<!doctype html>")
    assert "<link" not in html
    assert "src=" not in html
    assert "@import" not in html


def test_html_escapes_hostile_strings():
    info = make_info(label="<script>alert(1)</script>")
    finding = Finding(
        id="X-1",
        title="<img src=x onerror=alert(1)>",
        severity="low",
        category="test",
        description="d",
        rationale="r",
        evidence=[Evidence("classes.dex", "</pre><script>bad()</script>")],
    )
    masked = "<script>alert(1)</script>"
    report = build_report(info, [finding], [], score(info, [finding]))
    html = render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert masked.replace("<script>", "&lt;script&gt;") in html or "&lt;script&gt;" in html


def test_html_shows_inconclusive_wording_for_packed_apps():
    info = make_info(packer_hints=["jiagu"], coverage=0.3)
    report = build_report(info, [], [], score(info, []))
    html = render_html(report)
    assert "inconclusive" in html.lower()
    assert "dynamic scan" in html


def test_writers_create_parent_directories(tmp_path):
    report = sample_report()
    json_path = write_json(report, tmp_path / "nested" / "report.json")
    html_path = write_html(report, tmp_path / "nested" / "report.html")
    assert json.loads(json_path.read_text(encoding="utf-8"))["apk"]["package"] == "com.example.app"
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")
