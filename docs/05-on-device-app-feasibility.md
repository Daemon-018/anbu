# 05 — Could this be an Android app that scans every APK a user installs?

Short answer: **yes for installs routed through your app, yes for scanning installed apps afterwards with consent, and no for intercepting Play Store installs before they happen.**

There are two different products hiding in the question:

- **Universal scanner** — "scan every install on the device, including Play Store,
  before it happens." **Not possible** for a Play app.
- **Gatekeeper installer** — "the user installs APKs *through* our app; it scans first,
  blocks dangerous files, and only then hands a clean file to the system installer."
  **Possible**, and it is the realistic version of the idea. The design is in
  [section 3.1](#31-gatekeeper-installer--the-design-that-works).

A normal third-party app cannot intercept installs made by *other* apps or by Google
Play. It *can* be the installer for APKs the user opens with it, and it *can* audit
apps after they are installed. Those are different capabilities with different
permissions, policies, and limits.

---

## 0. What is built today

The repo already contains a working **post-install auditor** in
[`android-app/`](../android-app/), built without Gradle. It is the manual-dashboard
shape from [section 3.3](#33-manual-audit-dashboard), not the gatekeeper installer.

**Implemented**

- Lists installed user apps (system apps optional) with a filter.
- Scans on demand, queued one at a time, with progress and cancel.
- Reads package metadata, requested permissions, exported components, the signing
  certificate, and best-effort DEX/asset strings from the installed APK.
- Scores with the same deterministic math as the CLI (a plain-JDK parity test checks
  `ScoreMath` against vectors generated from `anbu.score`), including bands, confidence,
  coverage, and the inconclusive state.
- Shows findings with severity, description, and quoted evidence; batch "Scan all user
  apps" gives a summary.
- Uninstall hand-off, including device-admin awareness and the post-uninstall state.
- Requests no `INTERNET` permission. Nothing is uploaded; cloud checks do not exist in
  the app.

**Not implemented yet (design only, later sections)**

- Gatekeeper installer (`ACTION_VIEW` / `ACTION_SEND` / `PackageInstaller`).
- New-app notification, package-list-diff inbox, or `WorkManager` background checks.
- First-scan settings / cloud toggle, scan history, per-version ignore.
- Verified-hash badge, report persistence across process death.
- Any on-device LLM, dynamic analysis, or native `.so` analysis.

Build with `android-app/build.sh`; run the scoring parity test with
`android-app/test/run.sh`. The app targets API 24+ and uses `QUERY_ALL_PACKAGES` to
enumerate packages, which is a restricted permission for Play distribution (section 4).

---

## 1. Verdict matrix

| Proposed capability | Possible? | Reality |
|---|---|---|
| User taps an APK → your app opens it, scans it, then installs it | **Yes** | Register as a handler for `application/vnd.android.package-archive`; scan; hand off to `PackageInstaller`. User must choose your app and allow "install unknown apps". |
| Be the installer that refuses dangerous files | **Yes, within your flow** | If you never create a `PackageInstaller` session, nothing is installed. The user can still install the same file through another app later. |
| Auto-install with no further taps once a file passes | **No** | The system confirmation dialog is mandatory for non-Device-Owner apps. "Auto" means auto-start the prompt. |
| Guarantee the installed bytes are the scanned bytes | **Yes** | Scan the cached copy, hash it, then install that exact file; never re-read the original URI (TOCTOU). |
| Become the default APK handler without the user choosing | **No** | Default-handler choice belongs to the user; some OEM file managers skip the chooser entirely. |
| Cover APKs installed by browsers/app stores that call `PackageInstaller` themselves | **No** | They never route the file through you. |
| User shares an APK to your app → scan | **Yes** | `ACTION_SEND` / `ACTION_VIEW`; most reliable across OEMs. |
| Scan an APK the user picks with a file picker | **Yes** | Storage Access Framework; always works, best fallback. |
| Automatically scan **every** sideloaded APK before install | **No** | Android has no third-party install-interception API. If the user opens the system installer, you are not in the path. |
| Scan a Play Store install **before** it happens | **No** | Google Play + Play Protect own that pipeline. The package-verifier role is system/privileged only. |
| Scan Play Store apps **after** they are installed, with the user's consent | **Yes** | Diff the installed package list on app open or in a periodic job (`firstInstallTime`), then prompt. Metadata always; code only if the installed APK is readable. Cannot prevent damage already done. |
| Get an automatic callback on every install | **No** | `ACTION_PACKAGE_ADDED` is **not** on the Android 8+ implicit-broadcast exemption list. Use package-list diffing and a prompt (section 3.2). |
| Read installed apps' metadata, permissions, signatures | **Yes** | `PackageManager` + `GET_SIGNING_CERTIFICATES`; package visibility rules apply. |
| Read installed apps' APK files and scan their code | **Depends** | `ApplicationInfo.sourceDir` is often readable, but not guaranteed on every Android/OEM. Test; fall back to metadata-only. |
| Silently uninstall a dangerous app | **No** (consumer) | Requires user confirmation, or Device Owner / enterprise provisioning. |
| Continuously monitor in the background in real time | **No** | Background limits + foreground-service type rules; `WorkManager` periodic minimum is ~15 min. |
| On-device LLM explains decompiled Java | **Weakly** | No jadx on-device; smali is token-heavy; 1–3B models are slow and coarse. |
| On-device ML risk score from features | **Yes** | TFLite/ONNX over permissions + API refs + manifest + cert; milliseconds. |
| Safely run the APK to observe behaviour on-device | **No** | No safe sandbox for untrusted apps inside a normal app; virtualisation hacks are fragile and policy-hostile. |
| Enterprise/MDM: block or silently install | **Yes, B2B** | Device Owner / managed profile. Different product, different buyer. |

---

## 2. Why install interception is not available

Android's install pipeline is deliberately closed:

1. **Play Store installs** are executed by Google Play through the system
   `PackageInstaller`. There is no callback you can register to inspect or veto them.
   You can learn about them *afterwards* by diffing the installed package list
   (section 3.2), but you cannot get in front of them.
2. **Package verification** (the "verify app" step before install) is performed by the
   system verifier — in practice Play Protect. Acting as a verifier requires the
   signature-level `PACKAGE_VERIFICATION_AGENT` permission; a Play app cannot get it.
3. **Sideloaded installs** go to the system installer chosen by the OS/OEM. Declaring
   the APK MIME type makes your app *an option* in the "Open with" chooser, not the
   default gate.
4. **Accessibility-service interception** (watching for the installer screen and drawing
   a warning) is technically possible but: fragile across OEMs, easy to break, and
   Google Play's Accessibility API policy forbids using accessibility for this kind of
   monitoring/automation in most cases. It is not a foundation for a product.
5. **Device Admin** is a dead end for consumer apps; modern management is Device Owner,
   which requires provisioning (enterprise/QR/zero-touch), not a Play install.

The key distinction: you cannot intercept *someone else's* install, but when the user
opens an APK **with your app**, your app is the one that starts the install. You own that
flow, so you decide whether a `PackageInstaller` session is ever created. That is not
interception — it is being the installer. The rest of this document is about how far
that control reaches.

So the honest product sentence is:

> "ANBU is an APK installer that scans before it installs. Files opened through
> ANBU get checked, and dangerous ones are blocked in that flow. Installs made
> outside ANBU — including Play Store installs — are not covered."

That sentence is defensible. "Scans everything you install automatically" is not.

---

## 3. What the app can actually do on-device

### 3.1 Gatekeeper installer — the design that works

This is the clarified idea: the user installs the APK *through* the app, the app scans
it automatically, installs it if it looks clean, and refuses if it looks dangerous.
That is buildable. "Automatic" means the scan starts automatically and the install is
one tap away; Android still shows its own confirmation dialog, and you cannot remove it
without Device Owner.

**Flow**

1. **Entry points**
   - `ACTION_VIEW` with MIME `application/vnd.android.package-archive`: user taps the APK
     in Files/Downloads/WhatsApp and picks ANBU (optionally "Always").
   - `ACTION_SEND`: user shares the APK to ANBU. Most reliable across OEMs.
   - In-app picker (`ACTION_OPEN_DOCUMENT`) for when the chooser or share sheet is
     bypassed or the APK lives somewhere awkward.
2. **Take a private copy.** Receive a `content://` URI, stream it into app-internal cache
   while computing SHA-256. Enforce a size cap and validate the ZIP structure. Never
   trust the filename or the declared MIME type.
3. **Fast path.** Check a local hash cache, then optionally a reputation lookup
   (VirusTotal hash). Known-bad → block immediately; known-good → short-circuit to
   install. Unknown → static scan.
4. **Static scan** (2–10 s budget, progress UI, hard timeout):
   `getPackageArchiveInfo` for package/permissions/signers, AXML/ARSC parse for
   components and resources, dexlib2 for API references and strings, rule engine +
   combinations, optional small TFLite model.
5. **Decision**
   - Clean (score below threshold, no critical finding): show "No known malicious
     signals" + coverage, then an **Install** button.
   - Suspicious: show findings and require an explicit "Install anyway" acknowledgement.
   - Dangerous (high band, or a BANKER/RANSOM/DROPPER combination): **do not create the
     install session by default**. Show the evidence and offer "Delete file". If you
     allow an override at all, bury it behind a second confirmation; some teams refuse
     overrides for the top band entirely.
6. **Install.** Create a `PackageInstaller.Session` (`SESSION_MODE_FULL_INSTALL`), write
   the exact cached bytes, `commit()` with a `PendingIntent` broadcast. Handle
   `STATUS_PENDING_USER_ACTION` by launching the system confirmation. The user confirms;
   the package is installed.
7. **Clean up.** Delete the cached APK after install/cancel; keep the hash and the
   report, not the file.
8. **Confirm.** The `PackageInstaller` session callback verifies the install came from
   your package (`InstallSourceInfo`), then optionally runs a post-install audit.

**Manifest and API requirements**

- `REQUEST_INSTALL_PACKAGES` + the user granting "install unknown apps" through
  `ACTION_MANAGE_UNKNOWN_APP_SOURCES`. Without it, `PackageInstaller` sessions fail.
- An exported activity with an intent filter for `VIEW`, category `DEFAULT`, and the APK
  MIME type. Optionally also `ACTION_INSTALL_PACKAGE` for legacy senders.
- `PendingIntent` with `FLAG_IMMUTABLE` on Android 12+; `PackageInstaller.SessionCallback`
  for status.
- A recent `targetSdk`; Android 14+ refuses to install packages targeting SDK < 23.
- For split APKs (`.apks`/`.xapk` are ZIPs of splits), write all splits into one session,
  verify they share package name and signer. An `.aab` is not directly installable.
- The system still enforces signature verification; your pre-check can additionally flag
  debug certs, expiry, and signer mismatches between splits.

**Threat model for the gate itself**

- **TOCTOU:** hash the cached copy and install that same file. Never re-resolve or
  re-download the original URI between scan and install.
- **Parser safety:** the APK is hostile input. Cap ZIP entries and uncompressed size,
  reject path traversal, parse in a separate process (`android:process=":scanner"`) with
  a watchdog so a malformed DEX cannot freeze the installer UI.
- **Cache hygiene:** internal storage only, not world-readable, deleted after use.
- **Bypass:** the user can still install the same file via another app; the gate protects
  the flow through your app, not the device.

**Hard limits**

- Only APKs that enter through your app are covered. Browsers and app stores that open
  their own `PackageInstaller` session bypass you, and so does Google Play.
- Default-handler choice is the user's, and some OEM file managers go straight to the
  system installer. Share-to-app and the in-app picker are the reliable fallbacks.
- System confirmation is mandatory: "auto-install" is auto-starting the confirmation.
- A packed or dropper APK can pass a static scan. The gate is only as good as the
  analysis, and the UI must say so.

**Play distribution risk**

`REQUEST_INSTALL_PACKAGES` is a restricted permission. Installer and app-store use is a
recognised category, but approval is not guaranteed for a security app. Plan a
signed-APK direct-download build as a fallback; the target audience already sideloads.

**Effort**

- Hackathon demo (picker/share → backend scan → report → system install prompt): 2–3 days.
- Credible gate MVP (Kotlin, on-device rules, install session, split handling): 2–3 weeks
  for one or two developers, plus the analysis core.
- Play approval: unknown; treat it as schedule risk, not engineering work.

### 3.2 Post-install auditor — the Play Store path

This is how you cover Play Store apps: **after** they install, detect them, **ask the
user to scan**, then report and offer uninstall. It cannot prevent the install or the
app's first run, so treat it as triage/cleanup, not protection.

**Detection: no install broadcast exists**

`ACTION_PACKAGE_ADDED` is not on the Android 8+ implicit-broadcast exemption list, so a
manifest receiver will not reliably receive Play Store installs. Use one of these:

- **On-open reconciliation (recommended).** Store a snapshot of installed packages
  (`packageName`, `versionCode`, `signer`, `firstInstallTime`) and diff it each time the
  user opens the app. New entries become "2 apps installed since your last scan".
  No special broadcast, no background service, and it works after force-stop.
- **Periodic `WorkManager` job** (15-minute minimum, subject to Doze) runs the same diff
  and posts "New app installed: X — scan it?" (needs `POST_NOTIFICATIONS` on 13+).
- **Runtime receiver** while your process is alive — useful during a session, not a
  guarantee.

`PackageManager.getInstalledPackages()` needs package visibility: `QUERY_ALL_PACKAGES`
(restricted; Google Play explicitly lists **antivirus apps** as a permitted use, subject
to the Permissions Declaration Form and prominent disclosure) or `<queries>` for a
narrower set. Without broad visibility the diff is partial, and the UI must say so.

**Scanning an installed app**

- Read `ApplicationInfo.sourceDir` (base) and `splitSourceDirs` (config splits). These
  paths are usually readable, but not guaranteed on every Android/OEM. If the stream
  fails, degrade to **metadata-only**: package, version, permissions, signers,
  `InstallSourceInfo` (Play vs sideload), target SDK, flags.
- Hash base + splits, check the local cache and optional reputation service, then run
  the same static extractor as the CLI: manifest, certificate, DEX API references,
  strings, rules, combinations.
- Permissions can be read from `PackageInfo` without parsing the APK, so metadata-mode
  scans are still useful (over-permissioned apps, debug certs, impersonation).

**Consent and UX**

- Prompt, never silent: "New app installed: X (from Play Store). Scan it?" → Scan /
  Later / Ignore. Scanning every installed app automatically is a privacy problem and
  a battery problem.
- Result screen: score, band, findings with evidence, coverage, **Uninstall** (fires
  `ACTION_DELETE` with a `package:` URI → system confirmation), and Ignore.
- Known-bad hash → high-priority notification and an immediate uninstall prompt.
- Keep a local history so the user can see "scanned on install" status per app.

**Hard limits**

- **Late by design.** The app may already have run, exfiltrated data, or downloaded a
  payload. Post-install scanning is damage assessment, not prevention.
- Cannot block or quarantine. Uninstall always needs the user's confirmation.
- Packed apps may be unreadable or unanalysable; report inconclusive.
- `sourceDir` readability and package visibility vary by version/OEM; declare coverage.
- Force-stopped apps do not run WorkManager jobs until the user opens them again.

**Play distribution**

This path does **not** need `REQUEST_INSTALL_PACKAGES`, so it is materially easier to
ship than the gatekeeper installer. The main review item is `QUERY_ALL_PACKAGES`: it is
a restricted permission, but "antivirus apps" are explicitly listed as a permitted use,
provided broad visibility is core functionality, declared in the Permissions Declaration
Form, and disclosed to users. Approval is still not automatic; a narrower `<queries>`
build is the fallback.

**Effort:** ~1 week for detection + inbox + scan + uninstall flow once the analysis core
exists; a 1–2 day demo can do on-open diff + manual scan.

Screen-level detail, copy and acceptance criteria: [`06-auditor-screen-spec.md`](06-auditor-screen-spec.md).

### 3.3 Manual audit dashboard

- "Scan all installed apps" (user-initiated), sorted by risk.
- Requires broad package visibility: `QUERY_ALL_PACKAGES` is a **restricted** permission
  on Play. Security/antivirus use is an allowed category with a declaration and
  justification, but approval is not guaranteed. Without it, use `<queries>` for
  specific packages and accept partial coverage.
- Useful for stalkerware/spyware discovery, which is a real consumer need.

### 3.4 On-device analysis limits

| Layer | On-device feasibility |
|---|---|
| Manifest, permissions, certs, components | Excellent |
| DEX string/API-reference extraction (dexlib2) | Good, cap size/time |
| Call graph / taint-lite | Possible but memory-heavy on large apps |
| Java decompilation (jadx) | Not practical on-device |
| LLM explanation of smali | Poor-to-mediocre; slow, expensive in RAM |
| Small ML classifier on features | Good; train offline, ship 1–5 MB model |
| Native `.so` analysis | Very limited (strings/imports only) |
| Dynamic behaviour | Not safely possible |

**Practical split:** on-device does cheap, private, instant triage (hash + rules +
features + TFLite). The backend does deep static analysis and LLM explanation. That is
also how the mobile app stays under Play's size limits and battery expectations.

---

## 4. Google Play constraints to design around

| Constraint | Impact |
|---|---|
| `QUERY_ALL_PACKAGES` is restricted | Needed to enumerate installed apps; declare "security/antivirus" use, expect review |
| `REQUEST_INSTALL_PACKAGES` is restricted | Needed for the gatekeeper installer; installer/app-store use is recognised, but a security scanner may be rejected |
| Accessibility API policy | Do not use it to watch installer screens or automate UI |
| Device admin | Not viable for consumer security apps |
| Background execution + FGS types (Android 14+) | No always-on real-time monitor; use WorkManager + package-list diffing |
| Notification permission (Android 13+) | Ask in context; audit notifications are the product |
| Target SDK requirements | Must track recent Android versions |
| App size (AAB base module limits) | No bundled multi-GB LLM; use download-on-demand or backend |
| User-data + deceptive-claims policy | Clear consent, no "100% safe" claims, privacy policy, data deletion |
| Developer verification for sideloading (rolling out) | The sideload-gate niche may shrink over time; verify current rules |

Also: your own app will be scanned by Play Protect, and a security app that asks for
dangerous permissions is a juicy target for attackers. Minimise permissions; never
request SMS/contacts/accessibility for a scanner.

---

## 5. What users would actually get

Realistic value proposition for the Indian market (where APK scams arrive over WhatsApp):

- **"Audit my phone"** for stalkerware/spyware, user-initiated — **this is what the
  shipped app does today.**
- **"What is this app doing?"** explained in plain language with evidence — **shipped.**
- **"Check before you install"** for any APK the user opens or shares — future installer
  flow, not in the current app.
- **"Warn me about new apps"** on next open or via a periodic check, then scan on consent
  — future detection/inbox work.

What it cannot promise:

- Protecting Play Store installs before they happen.
- Blocking installation automatically.
- Detecting a packed app's real behaviour without a backend/dynamic analysis.
- Guaranteeing safety when it finds nothing.

Wording matters: "No known malicious signals" + coverage + confidence, never "Safe".

---

## 6. Effort and environment

| Piece | Effort (1–2 devs) | Notes |
|---|---|---|
| Analysis core (reusable, Python) | 1–2 weeks | Same core as the CLI/API |
| Android app: picker/share/open-with, report UI | 2–3 weeks | Kotlin, Compose, no exotic deps |
| On-device extractor (manifest + dexlib2 + rules) | 2–3 weeks | Dex parsing and edge cases are the time sink |
| Installer flow (`PackageInstaller`) | 3–5 days | Permission + OEM quirks + Android 14/15 changes |
| Post-install auditor | 1 week | Package diff + visibility + notification UX |
| Cloud backend + consent/privacy | 1–2 weeks | Reuse API from doc 03 |
| Play policy review / declarations | uncertain | The schedule risk is approval, not code |
| On-device LLM | 2–4 weeks | Often not worth it vs backend |

**This dev machine cannot run it:** there is no emulator, no `/dev/kvm`, and no `adb`
here, so the APK cannot be installed or exercised. The build itself is reproducible
without Gradle: `android-app/build.sh` drives `aapt2`, `javac`, `d8`, `zipalign`, and
`apksigner` directly and runs the score-parity test first. Use a real phone or an
emulator elsewhere for runtime testing; use Android Studio or a CI runner if you want
Gradle tooling.

A hackathon demo is feasible in 2–3 days if the scope is: file picker → upload/hash →
backend score → report screen. Skip the installer role and the on-device DEX parser for
the demo; show them as roadmap.

---

## 7. Recommended product shape

The repo already ships the first half of this shape: the analysis core plus a manual
post-install auditor. The gatekeeper installer below is the next product step, not a
prerequisite.

1. **Ship the analysis core as a service** (docs 01–03). It is the hard part and is
   reusable by CLI, web, and mobile.
2. **Ship the gatekeeper installer as the Android app**: scan on entry, block the
   dangerous band, install the clean file through `PackageInstaller`. It should also be
   honest about its coverage:
   - registers for APK `VIEW`/`SEND` + in-app picker;
   - computes hash + manifest features locally, calls the backend with consent;
   - displays score, findings, evidence, coverage;
   - optionally offers "Install" through `PackageInstaller` (if the permission is
     approved) and "Uninstall" via a system intent;
   - includes a post-install audit screen fed by a package-list diff (there is no
     manifest install broadcast on modern Android).
3. **Do not build** accessibility interception, silent install, on-device dynamic
   analysis, or an on-device 7B model.
4. **Position it as a pre-install checker for sideloaded APKs**, not as a replacement
   for Play Protect. That claim is true, useful, and defensible to Google Play review.

If the goal is a consumer product rather than a hackathon, validate the niche first:
Google's tightening of sideloading (developer verification, advanced protection) may
change how much friction exists in 2027. The backend/analysis capability survives either
way; the installer form factor may not.
