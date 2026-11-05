from __future__ import annotations

from anbu.rules import load_pack, run_combos, run_rules
from tests.conftest import make_component, make_info

SMS_REF = "Landroid/telephony/SmsManager;->sendTextMessage"
LOADER_REF = "Ldalvik/system/DexClassLoader;-><init>"


def bank_apk():
    return make_info(
        permissions=[
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        api_refs=[SMS_REF],
        urls=["http://203.0.113.10:8080/gate"],
        components=[make_component("com.example.SyncService")],
        intent_actions=["android.provider.Telephony.SMS_RECEIVED"],
    )


def test_sms_permission_rule_quotes_the_manifest():
    findings = {finding.id: finding for finding in run_rules(bank_apk())}
    assert findings["PERM-01"].severity == "high"
    quotes = [evidence.quote for evidence in findings["PERM-01"].evidence]
    assert "android.permission.RECEIVE_SMS" in quotes
    assert all(e.artifact == "AndroidManifest.xml" for e in findings["PERM-01"].evidence)


def test_banking_combo_fires_when_all_parts_are_present():
    findings = run_rules(bank_apk())
    combos = [combo.id for combo in run_combos(findings)]
    assert "BANKER" in combos
    assert "OTP-STEALER" in combos


def test_benign_app_triggers_nothing():
    info = make_info(
        permissions=["android.permission.VIBRATE"],
        strings=["Dice roll"],
        certs=[],
    )
    assert run_rules(info) == []
    assert run_combos([]) == []


def test_api_rule_needs_every_part():
    partial = make_info(api_refs=["Landroid/webkit/WebView;->addJavascriptInterface"], strings=[])
    findings = {finding.id for finding in run_rules(partial)}
    assert "API-04" not in findings

    full = make_info(
        api_refs=[
            "Landroid/webkit/WebView;->addJavascriptInterface",
            "Landroid/webkit/WebSettings;->setJavaScriptEnabled",
            "Landroid/webkit/WebView;->loadUrl",
        ]
    )
    assert "API-04" in {finding.id for finding in run_rules(full)}


def test_runtime_loader_rule_matches_dex_class_loader():
    info = make_info(api_refs=[LOADER_REF], permissions=["android.permission.REQUEST_INSTALL_PACKAGES"])
    findings = {finding.id: finding for finding in run_rules(info)}
    assert findings["API-02"].evidence[0].artifact == "classes.dex"
    assert findings["API-02"].evidence[0].quote == LOADER_REF


def test_packer_rule_quotes_the_marker_it_matched():
    info = make_info(
        packer_hints=["qihoo/jiagu"],
        packer_evidence={"qihoo/jiagu": "libjiagu"},
        sources={"libjiagu": "lib/arm64-v8a/libjiagu.so"},
        native_libs=["lib/arm64-v8a/libjiagu.so"],
        coverage=0.3,
    )
    findings = {finding.id: finding for finding in run_rules(info)}
    assert findings["ID-05"].evidence[0].artifact == "lib/arm64-v8a/libjiagu.so"


def test_debug_certificate_is_reported():
    from tests.conftest import make_cert

    info = make_info(certs=[make_cert(subject="CN=Android Debug, O=Android", debug=True)])
    assert "ID-01" in {finding.id for finding in run_rules(info)}


def test_every_rule_has_quotable_evidence():
    """No rule may fire with an empty evidence list."""
    findings = run_rules(bank_apk())
    assert findings
    for finding in findings:
        assert finding.evidence, finding.id


def test_rule_pack_ids_are_unique():
    pack = load_pack()
    ids = [rule["id"] for rule in pack["rules"]]
    assert len(ids) == len(set(ids))
    combo_ids = [combo["id"] for combo in pack["combos"]]
    assert len(combo_ids) == len(set(combo_ids))
    for combo in pack["combos"]:
        assert set(combo["finding_ids"]).issubset(set(ids))
