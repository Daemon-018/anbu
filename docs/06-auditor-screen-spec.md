# 06 — Post-install auditor: screen and interaction spec

Scope: the Android UI for scanning **already-installed** apps, including Play Store
installs, after the user consents. Detection is a package-list diff, not a broadcast
(see [`05-on-device-app-feasibility.md`](05-on-device-app-feasibility.md#32-post-install-auditor--the-play-store-path)).

This spec covers four flows: **detection prompt → scan progress → findings → uninstall**,
plus the states that keep them honest (inconclusive, metadata-only, offline, interrupted).

Related: score bands in [`02-risk-scoring.md`](02-risk-scoring.md#44-step-4--bands-confidence-coverage),
evidence contract in the same document.

---

## 1. Principles

1. **Never scan without consent.** Detection may be automatic; scanning is always a user
   action (notification action, inbox button, or "Scan all").
2. **Never say "safe".** Use "No known malicious signals" and always show coverage.
3. **One primary action per screen.** Uninstall is primary only when the evidence
   justifies it.
4. **Evidence in two taps.** Any score or verdict must reach a quoted artifact in ≤2 taps.
5. **Late is not prevention.** The UI says the app may already have run; it does not
   imply the device is now protected.
6. **No silent uninstall, ever.** Uninstall always goes through the system dialog.
7. **No nagging.** One prompt per app version; "Ignore" is respected until the app
   updates.

---

## 2. Screen map and state machine

| ID | Screen | Purpose |
|---|---|---|
| A1 | System notification | Prompt to scan a newly detected app |
| A2 | New-apps inbox | Batch list of unscanned/ignored apps |
| A3 | First-scan disclosure | Explain what is read and what leaves the device |
| A4 | Scan progress | Stages, percent, cancel |
| A5 | Result — verified malware | Known-bad match, uninstall-led |
| A6 | Result — high/critical | Heuristic dangerous, uninstall-led |
| A7 | Result — suspicious | Review-led, uninstall available |
| A8 | Result — low/clean | Reassurance without a safety claim |
| A9 | Result — inconclusive / limited | Packed, metadata-only, low coverage |
| A10 | Findings list | All findings, severity-sorted |
| A11 | Finding detail | Evidence, explanation, confidence |
| A12 | Uninstall handoff | System dialog + return handling |
| A13 | Post-uninstall | Confirmation, report, next action |
| A14 | History / app detail | Past scans, ignored and uninstalled entries |
| A15 | Error / interrupted | Timeout, parser failure, app removed |

```text
DETECTED -> PROMPTED -> SCANNING -> RESULT_*
                |           |          |
                |           +-> INTERRUPTED / FAILED
                +-> IGNORED (per version)

RESULT_VERIFIED_MALWARE / HIGH / CRITICAL / SUSPICIOUS
    -> UNINSTALL_HANDOFF -> UNINSTALLED | UNINSTALL_CANCELLED
    -> IGNORED (per version)

App update (versionCode/lastUpdateTime changes) -> DETECTED again
```

**Precedence:** verified malware > critical combo > score band > coverage caveat.
A packed app with a verified hash is still verified malware; a packed app with no match is
inconclusive, never "clean".

---

## 3. Detection prompt

### 3.1 Where it appears

| Surface | When | Notes |
|---|---|---|
| Notification (A1) | Periodic check or on-open diff finds a new package | Batched if several |
| In-app inbox (A2) | User opens the app | Always available, even if notifications are denied |
| Home banner | Only when ≥1 unscanned app and the user has not dismissed it this session | Dismiss hides for the session, not forever |

**No notification for clean results.** Notify on detection, and on completion only when
the band is suspicious or worse.

### 3.2 Notification spec

Channel `app_checks` (default importance). Channel `urgent_findings` (high importance)
is used only for verified malware and is opt-in in settings.

| Case | Title | Body | Actions |
|---|---|---|---|
| Single app | `New app installed` | `LoanApp was installed from Play Store. Scan it for risky behaviour?` | `Scan`, `Later` |
| Batch (2–5) | `3 new apps installed` | `Scan them for risky behaviour?` | `Scan all`, `Later` |
| >5 | `7 new apps installed` | `Open ANBU to review them.` | `Open` |
| Verified malware found | `LoanApp may be dangerous` | `A known malware signature was found. Review and uninstall.` | `Review`, `Uninstall`* |
| Suspicious result | `LoanApp has risky behaviour` | `3 findings need your attention.` | `Review` |

\* The `Uninstall` action deep-links to A5 with the uninstall button focused; it must not
fire the system dialog directly from the notification (accidental taps).

Rules:

- One notification per `packageName + versionCode`. Re-prompt only on update.
- Group by app; never stack more than one notification per package.
- Tapping the body opens the result if scanned, otherwise the scan disclosure/progress.
- If `POST_NOTIFICATIONS` is denied, skip A1 silently; A2 still works, and a one-time
  in-app card explains how to enable prompts. Do not block the app.
- Notification actions use immutable `PendingIntent`s with explicit components.

### 3.3 In-app inbox (A2)

Wireframe:

```text
┌──────────────────────────────────────────┐
│ New apps since your last scan       3    │
│                                          │
│ [icon] LoanApp                           │
│        Play Store · installed 2 min ago  │
│        [ Scan ]              [ Later ]   │
│                                          │
│ [icon] Flashlight Pro                    │
│        Sideloaded · installed 1 h ago    │
│        [ Scan ]              [ Ignore ]  │
│                                          │
│              [ Scan all (3) ]            │
└──────────────────────────────────────────┘
```

- Rows sorted newest first; ignored rows sink to a collapsed "Ignored" section with a
  `Scan again` action.
- Each row shows installer source: `Play Store`, `Sideloaded`, or the installer package
  name when unknown.
- `Later` keeps the row in the inbox. `Ignore` suppresses prompts for that version and
  records the decision in history.
- Batch scan runs sequentially with a queue indicator (`Scanning 2 of 3`); a failure in
  one does not stop the rest.

---

## 4. First-scan disclosure (A3)

Shown once per install of ANBU, before the first scan. A notification action counts
as consent for that app, but the disclosure is still shown the first time.

Copy:

> **Before ANBU scans**
>
> ANBU reads this app's package details, permissions, signature, and — when Android
> allows it — its code, on your device.
>
> Cloud checks are **off** by default. If you turn them on, only the app's SHA-256 and
> scan result are sent, not the app itself.
>
> A scan can find risky behaviour but cannot guarantee an app is safe. Apps can hide
> behaviour or download code later.

Actions: `Continue` (primary), `Cloud checks` toggle (secondary, inline), `Learn more`
(opens the methodology page). No "Don't show again" needed; it is once per install.

If the APK file is known to be unreadable on this device, the disclosure adds:
`On this device, ANBU may be able to inspect only the app's details, not its code.`

---

## 5. Scan progress (A4)

Wireframe:

```text
┌──────────────────────────────────────────┐
│  Scanning LoanApp                        │
│                                          │
│  [icon]  com.loanapp.fast                │
│          Play Store · v3.2.1             │
│                                          │
│  ✓ Reading app details                   │
│  ✓ Checking signature                    │
│  ● Inspecting code              61%      │
│  ○ Checking reputation                   │
│                                          │
│  [===============--------]               │
│  Usually takes 5–15 seconds              │
│                                          │
│              [ Cancel ]                  │
└──────────────────────────────────────────┘
```

Stages:

1. `Reading app details` — metadata, always available.
2. `Checking signature` — signer, scheme, debug/expiry flags.
3. `Inspecting code` — base + splits; determinate percent from classes/files processed.
4. `Checking reputation` — skipped offline or with cloud checks off.
5. `Preparing report`.

Behaviour:

- First stage appears within 300 ms. Never show a fake percentage; use indeterminate until
  a real denominator exists.
- If the whole scan finishes under 800 ms, go straight to the result (no progress flash).
- Hard timeout 30 s. On timeout, show A9/A15 with partial findings and a `Scan again`
  action; do not present a clean verdict.
- `Cancel` stops immediately, discards partial findings, returns to A2 with
  `Scan cancelled`. No confirmation dialog.
- Scan runs in the app process while the app is alive. If the process dies, the entry
  becomes `Interrupted` (`Scan again`); the UI must not promise background completion.
- Progress updates are announced politely to screen readers; the bar has a descriptive
  `contentDescription` (`Scanning code, 61 percent`).

---

## 6. Result screens

### 6.1 Common header

- App icon, label, package name (small, monospace), version.
- Source chip: `Play Store`, `Sideloaded`, or installer package.
- Scan mode chip: `Full scan`, `Details only`, or `Offline scan`.
- Score block: number, band label, and a one-line summary. The score is never shown
  without the band and coverage.

Score block accessibility label: `Risk score 78 out of 100, high risk`.

### 6.2 A5 — Verified malware

Wireframe:

```text
┌──────────────────────────────────────────┐
│ [icon] LoanApp                           │
│        com.loanapp.fast · v3.2.1         │
│                                          │
│  KNOWN MALWARE                           │
│  Matched a known malware signature.      │
│  Detected by 23 security engines.        │
│                                          │
│  [ Uninstall ]        [ Not now ]        │
│                                          │
│  [ See details ]                         │
│                                          │
│  This app may have already run.          │
└──────────────────────────────────────────┘
```

- No numeric score emphasis; the known-bad badge dominates. Keep the score in details.
- No "Keep app" action. `Not now` dismisses and records the decision; the user can still
  leave the app installed, but the product does not endorse it.
- `Uninstall` → A12.
- Evidence is one tap away (`See details` → A10/A11).

### 6.3 A6 — High / critical heuristic

```text
┌──────────────────────────────────────────┐
│ [icon] LoanApp                           │
│ 78  HIGH RISK                            │
│ Reads SMS and forwards message contents  │
│ to a remote endpoint.                    │
│                                          │
│ Inspected 61% of code · 3 findings       │
│                                          │
│ [ Uninstall ]     [ See 3 findings ]     │
│                                          │
│ Keep app (not recommended)               │
└──────────────────────────────────────────┘
```

- `Uninstall` primary; `See findings` secondary; `Keep app` is a low-emphasis text
  action behind a confirmation:
  > **Keep this app?** It shows behaviour commonly used to steal data. ANBU will
  > keep the report and stop prompting for this version.
  > `[ Keep app ]` `[ Cancel ]`
- Log the override locally as a false-negative candidate.

### 6.4 A7 — Suspicious (45–69)

- Primary: `Review findings`.
- Secondary: `Uninstall`.
- Tertiary: `Keep app` (no scary dialog; a single confirmation).
- Summary must name the top behaviour, not just "risky permissions".

### 6.5 A8 — Low / clean

```text
┌──────────────────────────────────────────┐
│ [icon] Notes Lite                        │
│ 12  NO KNOWN MALICIOUS SIGNALS           │
│ Checked permissions, signature, and 84%  │
│ of code. Nothing matched our detections. │
│                                          │
│ 1 low-risk finding                       │
│                                          │
│ [ Done ]            [ See details ]      │
└──────────────────────────────────────────┘
```

- Never a green shield with "Safe". Use a neutral check plus the explicit limitation:
  `No scan can guarantee an app is safe.`
- If mode is `Details only`, this screen is not used; show A9.

### 6.6 A9 — Inconclusive / limited inspection

Triggers: coverage <35%, packer detected, metadata-only, parser failure on most classes.

```text
┌──────────────────────────────────────────┐
│ LIMITED INSPECTION                       │
│ This app is packed, so most of its code  │
│ could not be read.                       │
│                                          │
│ What we checked: permissions, signature, │
│ 18% of code.                             │
│                                          │
│ [ Scan on another device? ]  [ Close ]   │
└──────────────────────────────────────────┘
```

- No numeric score in the headline; if a partial score exists, label it
  `Partial score, low confidence`.
- Actions: `Close`, `See what we found`, and (if cloud checks are available)
  `Request deep scan`. Never imply the app is safe.
- Metadata-only variant adds: `Android did not allow ANBU to read this app's code on
  this device.`

---

## 7. Findings

### 7.1 List (A10)

- Sorted by severity, then confidence, then category.
- Row: severity icon + label (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), title, category,
  confidence (`High/Medium/Low`), chevron.
- Header: `3 findings` + coverage chip. If zero findings: `No findings` with the list of
  what was checked and the limitation sentence.
- Filter chips only if >8 findings: `All`, `High and critical`, `Data and privacy`,
  `Network`, `Permissions`.

### 7.2 Detail (A11)

```text
┌──────────────────────────────────────────┐
│ HIGH · Sends SMS to a remote endpoint    │
│ Category: SMS interception               │
│ Confidence: high · Verified evidence     │
│                                          │
│ What we saw                              │
│ A broadcast receiver for incoming SMS    │
│ forwards the message body to a URL       │
│ stored in resources.                     │
│                                          │
│ Why it matters                           │
│ This is how one-time passwords are       │
│ stolen from banking apps.                │
│                                          │
│ Evidence                                 │
│ smali/com/loanapp/sync/SmsReceiver.smali │
│ lines 112–140                            │
│ ┌──────────────────────────────────────┐ │
│ │ invoke-virtual {v0, v1},             │ │
│ │ Landroid/telephony/SmsManager;->      │ │
│ │ sendTextMessage(...)                 │ │
│ └──────────────────────────────────────┘ │
│ [ Copy evidence ]                        │
│                                          │
│ MITRE ATT&CK Mobile: T1412               │
│ Static observation, not runtime proof.   │
│                                          │
│ Was this finding accurate?  [Yes] [No]   │
└──────────────────────────────────────────┘
```

Rules:

- Evidence quotes are not clickable and never auto-open URLs.
- Show `Verified evidence` only when the quote passed the artifact check; otherwise show
  `Unverified` and downgrade the row. Unverified findings are never counted as critical.
- Long quotes scroll inside a bounded monospace block with a copy button.
- The feedback control stores locally; upload only with the user's cloud consent.
- No raw decompiled file dumps in the UI; evidence is the specific lines that matter.

---

## 8. Uninstall flow (A12 → A13)

### 8.1 Handoff

1. User taps `Uninstall`.
2. If the app is an active device admin, do **not** fire `ACTION_DELETE`; show:
   > **This app has device administrator access.** Android will not uninstall it until
   > you turn that off. Open Settings → Security → Device admin apps, turn it off, then
   > try again.
   > `[ Open settings ]` `[ Cancel ]`
3. Otherwise fire `Intent.ACTION_DELETE` with `package:<name>` — the OS shows its own
   confirmation. ANBU never claims it can uninstall silently.

### 8.2 Return handling

On return, check whether the package still resolves:

| Outcome | UI |
|---|---|
| Package gone | A13: `LoanApp was uninstalled.` + `View report` + `Done`; history status `Uninstalled` |
| Still installed | Snackbar `Uninstall cancelled`; remain on the result screen; no repeat prompt |
| System error | `Android could not uninstall this app.` + `Try again` + `Details` |

### 8.3 A13 — Post-uninstall

```text
┌──────────────────────────────────────────┐
│ ✓ Uninstalled                            │
│ LoanApp was removed from this device.    │
│                                          │
│ [ View report ]              [ Done ]    │
└──────────────────────────────────────────┘
```

- The report remains in history even though the app is gone; mark it
  `App no longer installed`.
- Do not auto-scan another app; return to A2 with the next item highlighted.
- No celebration animation for a malware removal; keep it factual.

---

## 9. History and ignored apps (A14)

- Grouped by date; each row: icon, label, band chip, scan mode, timestamp, status
  (`Scanned`, `Ignored`, `Uninstalled`, `Interrupted`).
- Tapping opens the stored report snapshot; if the app is gone, show a non-blocking note.
- `Ignore` is per `packageName + versionCode`. An app update resets it to `Detected` and
  may prompt again.
- Retention: 30 days by default; `Clear history` deletes all reports locally and any
  server-side copies via the delete endpoint.

---

## 10. Error and edge states (A15)

| Situation | UI |
|---|---|
| APK unreadable | A9 metadata-only variant; `Code not accessible on this device` |
| Parser crash / malformed APK | `Could not inspect this app's code.` + metadata findings + `Report ID` + `Scan again` |
| Timeout (>30 s) | `Scan timed out. Showing what we found so far.` + partial findings; no clean verdict |
| Offline with cloud on | `Cloud checks unavailable. This is an on-device result.` + retry action |
| App uninstalled mid-scan | `App was removed during the scan.` + `Close` |
| Split APK partially readable | Coverage note: `Base APK inspected; 2 of 3 splits readable` |
| Multiple installs | Queue indicator; one report per app; failures isolated |
| Notification permission denied | In-app card explains prompts; inbox still works |
| Work profile app | Hidden or listed with `Work profile` chip if visible; note partial coverage |
| Rotation / process death during scan | Restore to `Interrupted`, offer `Scan again`; never show a half report as final |
| Font scale 200% | All text wraps; score block stacks vertically; actions remain 48dp |
| TalkBack | Severity read as text; progress announced; focus order follows visual order |

---

## 11. Data model

```text
AuditEntry {
  id, packageName, versionCode, label, iconRef,
  installerPackage, installSource, firstInstallTime, lastUpdateTime,
  detectedAt, lastScanAt, scanMode,          // FULL | METADATA | OFFLINE
  status, score, band, confidence, coverage,
  findings[], reportId, ignored, uninstalledAt
}

Status = DETECTED | PROMPTED | SCANNING | CLEAN | LOW | SUSPICIOUS |
         HIGH | CRITICAL | VERIFIED_MALWARE | INCONCLUSIVE |
         INTERRUPTED | FAILED | IGNORED | UNINSTALLED
```

- `band` and `status` are derived from the score and findings, never stored independently
  of them.
- A report snapshot is immutable once written; rescanning creates a new entry.
- `reportId` links to the same JSON schema used by the CLI/API, so the mobile and web
  reports stay consistent.

---

## 12. Copy rules

| Do | Don't |
|---|---|
| `No known malicious signals` | `Safe`, `Secure`, `Clean` |
| `Inspected 61% of code` | `Full scan complete` when coverage is partial |
| `This app may have already run` | `Your device is now protected` |
| `Behaviour commonly used to steal data` | `This is definitely malware` (unless verified hash) |
| `Uninstall` | `Remove threat`, `Clean now` |
| `Not now` | `Allow risk`, `Ignore warning` (for verified malware) |
| `Limited inspection` | `Unknown` with no explanation |

All strings live in resources, are localisable (English first, Hindi/Telugu next), and are
never concatenated in code.

---

## 13. Acceptance criteria

- [ ] No scan starts without an explicit user action.
- [ ] Notification tap → scan starts in one tap; first-run disclosure appears once.
- [ ] A score is never rendered without band, coverage, and confidence.
- [ ] Any finding reaches its quoted evidence in ≤2 taps.
- [ ] Unverified LLM findings are visibly marked and never drive the primary action.
- [ ] Verified malware has no "Keep app" action; high-risk heuristic override requires a
      confirmation.
- [ ] Uninstall always uses the system dialog; device-admin case is handled.
- [ ] Uninstall cancel returns to the result without nagging.
- [ ] All A15 states have copy and a recovery action.
- [ ] Ignore is per version; an update re-prompts.
- [ ] TalkBack reads severity and score; contrast ≥4.5:1; targets ≥48dp; 200% font works.
- [ ] No package names, code, or findings leave the device without cloud consent.
- [ ] History retention and deletion match the privacy policy.

### Test matrix

| Case | Expected |
|---|---|
| Clean app, 84% coverage | A8, `Done`, no "safe" wording |
| Suspicious app | A7, review-led, uninstall available |
| High-risk heuristic | A6, uninstall primary, override confirmed |
| Verified malware | A5, no keep action, uninstall primary |
| Packed app, no match | A9 inconclusive, no score headline |
| Metadata-only | A9 variant, permissions/cert findings only |
| Offline | Offline chip, on-device result, no reputation claim |
| Timeout | Partial report, `Scan again`, no clean verdict |
| Cancel | Back to A2, `Scan cancelled`, no stored report |
| Uninstall success / cancel / admin | A13 / snackbar / settings guidance |
| 3 apps at once | Batch inbox, sequential scans |
| Notification denied | A2 still works |
| Rotation during scan | State restored, no duplicate scan |
| Process death | `Interrupted` + `Scan again` |
