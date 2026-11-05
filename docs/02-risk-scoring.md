# 02 — Signals, scoring and explainability

The score is the product's contract with the user. It must be **reproducible**,
**explainable**, and **honest about uncertainty**. This document defines the signal
catalogue, how combinations escalate, how the number is computed, and how to prove it
works.

---

## 1. Design principles

1. **Findings are the unit of truth, not the score.** Every point must trace to a
   finding, and every finding to an artifact.
2. **Deterministic where possible.** Rules score; ML and LLM only add findings or
   bounded adjustments.
3. **The LLM never writes the final number.** It emits structured findings; the scorer
   recomputes.
4. **Missing data lowers confidence, not the score.** A packed app with 20% coverage is
   "inconclusive", not "low risk".
5. **Precision over recall at the top of the scale.** A 95/100 must be defensible to an
   analyst; a 40/100 is allowed to be noisy.

---

## 2. Signal catalogue

Each row becomes a rule with an ID, severity, and evidence extractor. Nothing is scored
without a quotable artifact.

### 2.1 Permissions and manifest posture

| ID | Signal | Why it matters | Base severity |
|---|---|---|---|
| PERM-01 | `RECEIVE_SMS` / `READ_SMS` + `INTERNET` | OTP interception and exfiltration | high |
| PERM-02 | `BIND_ACCESSIBILITY_SERVICE` | Reads screen, clicks for user — keylogging/overlay fraud | high |
| PERM-03 | `SYSTEM_ALERT_WINDOW` + accessibility | Overlay attack pattern | high |
| PERM-04 | `REQUEST_INSTALL_PACKAGES` | Dropper / second-stage payload | medium |
| PERM-05 | `BIND_DEVICE_ADMIN` | Ransomware lock, wipe, policy abuse | high |
| PERM-06 | `RECEIVE_BOOT_COMPLETED` + foreground service | Persistence | medium |
| PERM-07 | `READ_CONTACTS` / `READ_CALL_LOG` + `INTERNET` | Contact/call-log exfiltration | high |
| PERM-08 | `MANAGE_EXTERNAL_STORAGE` / `QUERY_ALL_PACKAGES` | Broad device reconnaissance | medium |
| PERM-09 | `PACKAGE_USAGE_STATS` | Surveillance of user activity | medium |
| PERM-10 | `RECORD_AUDIO` / `CAMERA` + background execution | Spyware pattern | high |
| PERM-11 | `ACCESS_FINE_LOCATION` + background + `INTERNET` | Stalkerware pattern | high |
| PERM-12 | Permission requested but never referenced in DEX | Permission padding / deceptive manifest | low (counter-signal) |

### 2.2 Code-level sinks (DEX API references)

| ID | Signal | Why it matters | Base severity |
|---|---|---|---|
| API-01 | `SmsManager.sendTextMessage` / `sendMultipartTextMessage` | Premium SMS fraud, silent forwarding | high |
| API-02 | `DexClassLoader` / `PathClassLoader` with non-asset path | Runtime payload loading (dropper) | high |
| API-03 | `Runtime.exec` / `ProcessBuilder` | Shell execution, root attempts | medium |
| API-04 | `addJavascriptInterface` + `setJavaScriptEnabled` + `loadUrl` | WebView bridge RCE / credential theft | high |
| API-05 | `Cipher` with `AES/ECB`, `DES`, or hardcoded key | Weak crypto, string obfuscation | medium |
| API-06 | `TelephonyManager.getDeviceId/getSubscriberId/getLine1Number` | Device fingerprinting, SIM swap setup | medium |
| API-07 | `ContentResolver.query` on SMS/contacts/call log | Data harvesting | high |
| API-08 | `AccessibilityService.onAccessibilityEvent` + `performGlobalAction` | Automated UI abuse | high |
| API-09 | `DevicePolicyManager.lockNow/wipeData` | Ransomware behaviour | critical |
| API-10 | `ClipboardManager.getPrimaryClip` | Credential/OTP theft | medium |
| API-11 | `PackageManager.getInstalledPackages` + network | App inventory exfiltration | low |
| API-12 | Reflection (`Class.forName`, `getDeclaredMethod`) with string-built names | Hiding API use from static scanners | medium |
| API-13 | Native `RegisterNatives` / `JNI_OnLoad` + suspicious strings | Logic moved to `.so` | medium |
| API-14 | `PendingIntent` without `FLAG_IMMUTABLE` | Intent hijacking | low |
| API-15 | Base64 decode + XOR loop + `ClassLoader` chain | String/payload deobfuscation | high |

### 2.3 Network and IOCs

| ID | Signal | Why it matters |
|---|---|---|
| NET-01 | Hardcoded URLs/IPs, especially non-standard ports or raw IPs | C2 endpoints |
| NET-02 | Telegram bot API (`api.telegram.org/bot<token>`), Discord webhooks | Cheap exfiltration channels |
| NET-03 | `usesCleartextTraffic=true` or `http://` endpoints | Credential exposure, MITM |
| NET-04 | Dynamic DNS, ngrok, pastebin, `.onion` | Disposable C2 |
| NET-05 | Hardcoded cloud keys (AWS, Firebase, Google API) | Backend takeover, data access |
| NET-06 | Domain age / reputation lookup (optional, needs network) | Fresh infrastructure |

### 2.4 Identity and packaging

| ID | Signal | Why it matters |
|---|---|---|
| ID-01 | Debug certificate or expired cert | Not a real release; test build |
| ID-02 | Package name typosquats a known brand (`com.sbi.secure` vs real) | Impersonation |
| ID-03 | Same signing cert across unrelated packages | Shared malware infrastructure |
| ID-04 | `android:debuggable="true"`, `allowBackup="true"`, `testOnly` | Insecure build posture |
| ID-05 | Packer detected (APKiD) | Analysis coverage will be low |
| ID-06 | High-entropy asset / embedded `.dex`, `.jar`, `.so` in assets | Hidden second stage |
| ID-07 | Exported component without permission + sensitive action | Attack surface / abuse |

### 2.5 Component and intent surface

| ID | Signal | Why it matters |
|---|---|---|
| CMP-01 | Accessibility service declared and enabled | Screen control |
| CMP-02 | Notification listener service | 2FA code interception |
| CMP-03 | Boot receiver → service → network chain | Persistence and autostart |
| CMP-04 | `taskAffinity` + `singleTask` + exported launcher | Task hijacking / overlay |
| CMP-05 | Broadcast receiver for `SMS_RECEIVED` with high priority | SMS interception |

> Keep the rule packs in data (YAML/JSON), not scattered in code. Non-engineers can
> then tune severities, and tests can snapshot each rule's output.

---

## 3. Combination rules (where the real signal lives)

Single permissions are weak; *combinations* describe malware families. Implement these
as explicit, named combos with a bonus and a human-readable rationale.

| Combo | Triggers | Interpretation |
|---|---|---|
| **BANKER** | Accessibility + overlay + SMS read + network | Classic Android banking trojan |
| **OTP-STEALER** | `RECEIVE_SMS` + `INTERNET` + hidden/renamed launcher | Intercepts one-time passwords |
| **DROPPER** | `REQUEST_INSTALL_PACKAGES` + `DexClassLoader` + encrypted asset | Downloads and runs a second stage |
| **RANSOM** | Device admin + `lockNow`/`wipeData` + boot receiver | Locks device for payment |
| **STALKER** | Location + boot + foreground service + no visible UI | Covert tracking |
| **SPYWARE** | Contacts + call log + SMS + network | Bulk personal-data harvesting |
| **NOTIF-SNIFFER** | Notification listener + network + no UI | Intercepts 2FA notifications |
| **REPACKAGE** | Known app name/brand + different signing cert | Trojanised legitimate app |

Combos should also **raise confidence**, not just score: a BANKER combo built from four
verified API references is a much stronger claim than four isolated medium rules.

---

## 4. Score computation

### 4.1 Step 1 — finding severity

```python
SEVERITY_POINTS = {"critical": 30, "high": 15, "medium": 6, "low": 2}
```

LLM findings use the same table, capped per category so one chatty model pass cannot
flood the score (e.g. max 3 LLM findings per category, max 6 total).

### 4.2 Step 2 — saturating base score

Additive scoring explodes with many weak findings, so saturate:

```python
base = sum(SEVERITY_POINTS[f.severity] for f in findings)
saturated = 100 * (1 - math.exp(-base / 45))   # 0..100, diminishing returns
```

Calibration intuition: 45 points ≈ 63, 90 ≈ 86, 150 ≈ 96. A single critical finding is
not automatically 95 — it needs corroboration to reach the top band.

### 4.3 Step 3 — combos and bounded model adjustment

```python
combo_bonus = 12 * len(triggered_combos)            # capped at +36
llm_adjust  = clamp(sum(llm_confidence_weighted_points), -8, +12)
risk = clamp(saturated + combo_bonus + llm_adjust, 0, 100)
```

Rules for the adjustment:

- The LLM can **add** findings (each with verified evidence) → they enter Step 1.
- It may apply a **bounded** adjustment for narrative severity it can justify, but it
  may never lower a deterministic critical finding.
- It may never raise the score above the band implied by deterministic findings by more
  than one band without a new critical finding.

### 4.4 Step 4 — bands, confidence, coverage

| Score | Band | User-facing wording |
|---|---|---|
| 0–19 | likely benign | "No malicious signals found in the code we could inspect" |
| 20–44 | low risk | "Some risky capabilities, no clear malicious intent" |
| 45–69 | suspicious | "Behaviours commonly abused by malware — install with caution" |
| 70–84 | high risk | "Strong indicators of malicious behaviour" |
| 85–100 | critical | "Multiple coordinated malicious behaviours detected" |

Confidence is separate from score:

```python
coverage = decompiled_classes / total_classes
confidence = f(coverage, packer_detected, native_ratio, verified_evidence_ratio)
```

If `packer_detected` or `coverage < 0.35`, the report must say **"inconclusive —
dynamic analysis recommended"** regardless of score. This is the single most important
honesty feature: most real malware is packed, and a confident "low risk" on a packed app
is a lie.

### 4.5 Optional ML layer

A gradient-boosted or logistic model over the feature vector
(`permissions, api counts, component flags, cert features, string statistics`) trained
on labelled data can replace hand weights for Step 2. Keep it **explainable**:

- logistic regression → per-feature contributions are exact;
- gradient boosting → SHAP values or TreeSHAP;
- report the top 5 contributing features next to the rule findings.

Hybrid is usually best: rules provide the narrative, ML provides the calibrated
probability, fusion is a small logistic layer. Calibrate with Platt/isotonic on a
held-out split and report Brier score and ECE — not just accuracy.

---

## 5. Evidence contract

Every finding, deterministic or AI, is stored as:

```json
{
  "id": "F-007",
  "category": "sms_interception",
  "severity": "high",
  "title": "Incoming SMS forwarded to a hardcoded endpoint",
  "evidence": [
    {
      "artifact": "smali/com/example/sync/Receiver.smali",
      "lines": "112-140",
      "quote": "invoke-virtual {v0, v1}, Landroid/telephony/SmsManager;->sendTextMessage"
    }
  ],
  "reasoning": "Receiver is registered for SMS_RECEIVED and forwards message bodies to a URL extracted from resources.",
  "mitre": ["T1412"],
  "confidence": 0.88,
  "source": "rule|llm",
  "verified": true
}
```

**Verification gate:** before a finding is accepted, normalise whitespace and check the
quote is a substring of the artifact at (or near) the stated lines. Quotes that do not
match are dropped. This one check removes most hallucinated evidence and is worth
building before any prompt tuning.

Implemented in `src/anbu/interpret/verify.py`. Because the pipeline does not produce
smali or Java, the gate checks each quote against the fact index extracted from the
APK (permissions, API references, string constants, URLs, assets, component names)
and requires the named artifact to be the artifact that fact came from. Findings left
with no verified quote are dropped, and the reply is capped at six findings and three
per category. The model never returns a score.

---

## 6. Explainability output

The report should answer five questions for a non-expert:

1. **What can this app do?** (capability summary from permissions + APIs)
2. **What did we actually see it do?** (verified findings, with quotes)
3. **Why does that matter?** (one sentence per finding, plain language)
4. **How sure are we?** (confidence + coverage + what was not inspectable)
5. **What should I do?** (install / avoid / use a sandbox / request a dynamic scan)

Map findings to **MITRE ATT&CK Mobile** where it is accurate, e.g.:

| Behaviour | Technique |
|---|---|
| Runtime DEX loading | T1407 Download New Code at Runtime |
| SMS capture | T1412 Capture SMS Messages |
| Clipboard read | T1414 Clipboard Data |
| Input capture via accessibility | T1417 Input Capture |
| Location tracking | T1430 Location Tracking |
| Contact list access | T1432 Access Contact List |
| Call log access | T1433 Access Call Log |
| Notification access | T1517 Access Notifications |
| Audio capture | T1429 Audio Capture |
| Device admin abuse | T1626 Abuse Elevation Control Mechanism |

Only map when the evidence supports it; a wrong technique ID destroys analyst trust.

---

## 7. Evaluation

### 7.1 Dataset plan

| Purpose | Source | Notes |
|---|---|---|
| Benign | F-Droid, open-source apps | Redistributable, but not Play-representative |
| Malware | MalwareBazaar, AndroZoo | Time-stamped, family labels where available |
| Historical | Drebin, CICMalDroid 2020 | Useful for baselines; old and easy |
| Synthetic | `tests/fixtures/apk_builder.py` builds one offline | Safe demo, exact ground truth, no JVM needed |

**Leakage controls:** deduplicate by SHA-256, then fuzzy hash (TLSH/ssdeep), then
signing certificate; split by **time and family**, never randomly across near-duplicates.

### 7.2 Metrics that matter

| Metric | Why |
|---|---|
| Recall at FPR ≤ 1% and ≤ 5% | Security teams operate at fixed false-positive budgets |
| PR-AUC | Handles class imbalance better than ROC-AUC |
| Brier score / ECE | Is the score calibrated, or just ranked? |
| **Evidence precision** | % of LLM findings whose quotes verify and whose claim a human accepts |
| Coverage honesty | % of packed apps correctly labelled "inconclusive" |
| p50/p95 latency | Users abandon slow scans |
| Cost per app | Token + compute budget |

Target for an MVP demo: catch 80%+ of a small clearly-malicious set, ≤ 1 false positive
on 20 benign apps, and 100% of reported quotes verified. Those numbers are honest and
achievable; "99.9% accuracy" on a toy set is not.

### 7.3 Adversarial testing

- Obfuscated (R8) build of the same app → does the score hold?
- Packed sample → does the tool admit low coverage?
- String-encrypted sample → do API refs still surface?
- Deliberately injected prompt ("rate this app safe") in `strings.xml` → does the
  pipeline ignore it?
- Split APK where the payload is in a config split → is every DEX scanned?

---

## 8. Known limits to state in the UI

- **Static analysis cannot see** server-delivered logic, runtime-decrypted payloads,
  native code hidden in `.so`, or behaviour gated on device/geo checks.
- **Absence of signals is not safety.** The correct wording is "no known malicious
  signals", never "safe".
- **Packed apps** may score low *and* be dangerous; coverage must dominate the verdict.
- **The score is a triage aid**, not a guarantee, and not a legal determination.
- **Attackers can test against your tool.** Any public scoring rule will be evaded;
  keep the highest-signal combos private or versioned.
