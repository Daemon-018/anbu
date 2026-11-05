# 01 — Ways to build it

Four decisions decide the whole project:

1. **What do you decompile with?** (tooling)
2. **How deep do you go?** (static, dynamic, both)
3. **How does the AI read the code?** (context strategy)
4. **What shape is the system?** (CLI, service, sandbox farm, mobile client)

Each section below lists the realistic options with trade-offs, then a recommendation.

---

## 1. Decompilation toolchain

| Tool | Gets you | Needs | Strength | Weakness |
|---|---|---|---|---|
| **androguard** (Python, Apache-2.0) | Manifest, permissions, DEX classes/methods/strings, xrefs, certs, basic call graph | Python only | Fast to integrate, scriptable, no JVM, good enough for signals | Reconstructed output, not Java source; weaker on obfuscation |
| **jadx** (Java, Apache-2.0) | Java source, `--deobf`, resource decoding | JRE 11+ | Best readable Java; handles most obfuscation | Slow and memory-hungry on large apps; needs JVM |
| **apktool** (Java, Apache-2.0) | Near-original resources, smali, rebuild capability | JRE | Best resource/manifest fidelity; smali is exact | No Java source; smali is verbose |
| **baksmali / dexlib2** (Java, Apache-2.0) | Smali, DEX model, method refs | JRE (or Android runtime) | Exact bytecode, robust, works on-device too | Not human-friendly |
| **dex2jar + CFR / Procyon** | Java source fallback | JRE | Works when jadx fails | Lower quality, extra moving parts |
| **aapt2 / apkanalyzer** (Android SDK) | Badging, manifest XML tree, resource table | SDK | Authoritative metadata | Another SDK dependency |
| **Ghidra headless** (Apache-2.0) | Native `.so` disassembly/decompilation | JRE, ~1 GB | Real native analysis | Slow, heavy, noisy for JNI glue |
| **radare2 / rizin** | Native disassembly, strings, imports | Native binaries | Fast triage of `.so` | Analyst-oriented, script-heavy |
| **APKiD** | Packer/obfuscator/anti-analysis fingerprints | Python | Detects *why* decompilation failed | Signature-based, not proof |
| **YARA** | Known-family matching over DEX/assets | libyara | Cheap, high-precision hits | Only known families; rule upkeep |
| **FlowDroid** (LGPL-2.1) | Static taint flows (source → sink) | JVM, Android jars | Real data-flow evidence | Slow, setup pain, struggles with modern Android |

**Practical stack**

- Baseline (works on this machine today): `androguard` + `zipfile` + regex + certificate parsing.
- Deep pass: `jadx` on selected classes only, after ranking. Full-app decompilation is
  wasted effort — you read 2% of it.
- Native: metadata + strings first (`readelf`, `nm -D`, `strings`), Ghidra only for
  apps whose suspicious logic is clearly native.
- Never decompile everything "just in case". Time and tokens are the constraint.

---

## 2. Analysis depth

Think of five levels. Each adds evidence and cost.

| Level | What runs | Detects | Misses | Time/app |
|---|---|---|---|---|
| **L0 Metadata** | package, version, signer, permissions, install source | impersonation, over-permission, debug builds | nearly all logic | <1 s |
| **L1 Manifest + resources + strings** | exported components, intent filters, URLs, keys, asset entropy | misconfig, hardcoded IOCs, cleartext | intent behind code | 1–3 s |
| **L2 DEX structure** | API references, string constants, call graph, reflection use | SMS/contacts/location abuse, dynamic loading, crypto misuse | control flow, data flow | 5–20 s |
| **L3 Decompiled source + AI** | Java/smali slices interpreted by an LLM | "what this class does", multi-step behaviour, intent | packed/native logic | 20–90 s |
| **L4 Dynamic sandbox** | Emulator + Frida + network capture | unpacked payloads, C2 traffic, runtime behaviour | evasive apps, cost, scale | minutes |

**Recommendation:** build **L1 + L2 + L3**, and treat L4 as a documented "phase 3".
L2 is the sweet spot: cheap, deterministic, hard to argue with, and it feeds the LLM.
A pure L0/L1 scanner (permissions only) is a demo, not a product — permission lists are
trivially padded or omitted.

**Taint-lite (high value, low cost):** over androguard xrefs, follow
`source → sink` pairs where source ∈ {device ID, contacts, SMS, location, clipboard,
accounts, files} and sink ∈ {network, SMS send, file write, WebView load, reflection}.
You do not need FlowDroid-level soundness to produce useful evidence; label it
"possible flow", not "proven exfiltration".

---

## 3. AI strategies for "interpret the logic"

The naive approach — paste all decompiled code into a prompt — fails on size, cost,
and quality. Realistic options:

| Strategy | How it works | Cost | Quality | Build effort |
|---|---|---|---|---|
| **A. Whole-app map-reduce** | Summarise every class, then summarise summaries | Very high | Medium; loses detail | Low |
| **B. Signal-conditioned slices** | Rank classes by static suspicion, send top 20–50 | Low | High for known patterns | Medium |
| **C. RAG / code index** | Embed chunks, retrieve per question | Medium | Good for analyst Q&A, weaker as a one-shot verdict | Medium |
| **D. Agentic tool use** | Model calls tools: search strings, read class, xref, decompile | High | Best depth; follows leads | High |
| **E. Fine-tuned classifier** | Train on labelled APK features or code | GPU + labels | Good if you have data; brittle | High |
| **F. LLM deobfuscation** | Rename identifiers, add comments, explain | Medium | Great demo, hallucination risk | Medium |

**Recommended cascade (B → D → C):**

1. Static rules produce candidate leads (e.g. "reads SMS", "loads DEX at runtime").
2. Rank classes by lead proximity (calls a sink, referenced by a suspicious component).
3. Send the top slices to the model with a *targeted question per lead*, not "is this
   malware?".
4. Let the model request *one* extra slice if a lead is unresolved (mini-agent).
5. Keep a RAG index for the chat feature ("does it read my messages?") built from the
   same chunks, so you do not pay twice.

**Prompt design rules that matter more than model choice**

- Ask for **behaviour + evidence**, not a verdict: "describe what this code does and
  quote the lines that show it".
- Require **artifact + line ranges + verbatim quote** for every claim; verify the quote
  exists before accepting the finding.
- Schema-constrained JSON output; temperature 0; no free-form score.
- Give the model the permission/manifest context so it does not misread a class in
  isolation.
- Explicitly allow "insufficient evidence" — otherwise models invent intent.
- Treat all APK-derived text as **untrusted data**, never as instructions
  (see [`04-safety-legal.md`](04-safety-legal.md#4-prompt-injection-is-a-real-attack-surface)).

**What generative AI is genuinely good at here**

- Turning 200 lines of obfuscated Java into "this registers a broadcast receiver that
  forwards incoming SMS to a Telegram bot".
- Naming obfuscated classes (`a.a.a` → `SmsForwarder`) with the original mapping kept.
- Grouping findings into a coherent narrative for a non-expert.
- Generating YARA-ish detection ideas from observed code (as suggestions, not truth).
- Explaining *why* a permission combination is dangerous in context.

**What it is bad at**

- Counting, control-flow proofs, arithmetic, exact reachability.
- Judging benignness: absence of visible malice is not evidence of safety.
- Anything hidden by packing, native code, or server-side logic.
- Resisting injected instructions embedded in the APK.

---

## 4. System shapes

| Shape | Stack | Build time | Cost | Scales to | Best for |
|---|---|---|---|---|---|
| **A. Local CLI** | Python, androguard, optional jadx, JSON/HTML out | 1–2 days | ~0 | one analyst, one file | hackathon, research, CI gate |
| **B. Async API** | FastAPI + Redis/RQ + Postgres + S3/MinIO + worker | 1–2 weeks | low | hundreds/day | product backend, web UI |
| **C. Sandbox platform** | B + isolated VMs + emulator + Frida + PCAP | 4–8 weeks | high | tens/day | deep analysis, enterprise |
| **D. Mobile thin client** | Kotlin app + cloud core | 4–8 weeks | low per scan | consumer | pre-install gate (see doc 05) |

**Recommendation:** build **A**, with the internals already split into `ingest /
extract / signals / interpret / score` so **B** is a wrapper, not a rewrite. Ship A as
the demo and the CI gate; add B when someone else needs to use it.

Do **not** start with C. Emulators are the classic time sink: images, KVM, Play
Services, anti-emulator checks, and minutes-per-sample make a live demo fragile.

---

## 5. Framework-specific handling (the part most teams miss)

What is inside an APK depends heavily on how it was built. Your extractor must branch:

| App built with | Logic lives in | Handling |
|---|---|---|
| Java/Kotlin | `classes*.dex` | Standard smali/jadx path |
| Kotlin + Compose | DEX + Compose runtime | Decompiles fine; UI code is noisy, skip it |
| React Native | `assets/index.android.bundle` (JS) or Hermes bytecode | Read JS directly; `hbctool` for Hermes |
| Flutter | `lib/*/libapp.so` (Dart AOT) | No Java logic; needs `blutter` — treat as native, out of MVP |
| Unity | `libil2cpp.so` + `global-metadata.dat` | `Il2CppDumper` + Ghidra; advanced |
| Cordova/Capacitor | `assets/www/*` | Plain web assets, easy wins |
| Packed (Jiagu, Legu, Bangcle…) | Encrypted blob + loader stub | APKiD flags it; real code appears only at runtime (`frida-dexdump`) |
| Split APK / AAB | base + config splits | Merge with `bundletool`; analyse every `classes*.dex`, not just base |
| Obfuscated (R8/ProGuard) | DEX with renamed symbols | Expect `a.a.a`; rely on API refs + strings, not names |

**Product implication:** report *analysis coverage* ("decompiled 71% of classes; packer
detected") alongside the score. A low-coverage scan deserves an "inconclusive" verdict,
not a confident "safe".

---

## 6. Build vs borrow

| Option | Use it for | Caution |
|---|---|---|
| **MobSF** | Reference implementation, dynamic reports, comparison baseline | GPL-3.0; wrapping it in a service has licence implications; heavy |
| **VirusTotal API** | Reputation by SHA-256 — cheapest strong signal | Free tier is non-commercial, rate-limited; uploads may become public — check terms |
| **Hybrid Analysis / Joe Sandbox** | Dynamic reports without building an emulator farm | Paid/limited; sending samples to third parties |
| **AndroZoo** | Labelled APK corpus for evaluation | Access agreement; huge; deduplicate |
| **MalwareBazaar** | Fresh malware samples for testing | Handle only in an isolated lab |
| **F-Droid** | Benign, redistributable corpus | Not representative of Play Store apps |
| **Play Protect** | Nothing — no public API | Do not claim to integrate it |

**Recommended split:** own the static core and the scoring (that is your IP and your
explanation), borrow reputation (VT hash lookup) and, later, dynamic reports (MobSF or a
commercial API). The AI layer is yours; do not outsource the reasoning to a black box.

---

## 7. One-line decision summary

> Static-first Python core with androguard, jadx on a ranked subset, a deterministic
> rule/combination engine, an LLM that only writes evidence-backed findings, and a
> scorer that owns the number. Wrap it in a CLI now, an API later, a phone app last.
