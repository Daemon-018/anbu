# 03 — MVP, roadmap and demo

The failure mode for this project is building an emulator farm and a training pipeline
before producing a single report. This plan is ordered so that every checkpoint is
demoable.

---

## 1. MVP definition

**One command in, one report out:**

```bash
anbu scan samples/app.apk --out out/app.json --html out/app.html
```

Must produce: identity, permission table, verified findings with quotes, 0–100 score
with band and confidence, coverage statement, and a plain-language summary.

**Built today:** safe ingest, extraction, 37 rules and 7 combos, the class ranker and
slicer, the optional schema-constrained model pass with the evidence gate, the
deterministic scorer, JSON + HTML reports, the CLI gate, offline synthetic APK fixtures,
and an on-device Android post-install auditor (`android-app/`) that shares the same
scoring math. **Not built yet:** a jadx pass, hash reputation, report chat, the service
API, and the pre-install gatekeeper flow described in doc 05.

### Must have (48-hour MVP)

| # | Capability | Detail |
|---|---|---|
| 1 | Safe ingest | zip guards (entry count, uncompressed size, path traversal), SHA-256, size cap |
| 2 | Manifest extraction | package, version, SDK levels, permissions, components, flags, certs |
| 3 | DEX extraction | classes, methods, strings, API references, xrefs (androguard) |
| 4 | Rule engine | 25–40 rules from doc 02, data-driven severities |
| 5 | Combos | 6–8 named combinations with rationale |
| 6 | Ranker | score classes by sink proximity; select top 20–30 |
| 7 | LLM pass | targeted findings on selected slices, schema-constrained |
| 8 | Evidence verifier | quote must exist in artifact; drop otherwise |
| 9 | Scorer | saturating formula, combos, confidence, coverage |
| 10 | Report | JSON + self-contained HTML (no external assets) |
| 11 | Eval | 20 benign + 10 malicious, recorded metrics |

### Should have (if time permits)

- Hash reputation lookup (VirusTotal) — cheap, strong, one API call.
- `jadx` pass for the top classes instead of smali.
- Chat over one report: `anbu ask out/app.json "does it read SMS?"`.
- Prompt-injection guard + test fixture.
- Simple diff: two versions, what changed.

### Will not have (MVP)

- Dynamic analysis / emulator.
- Trained ML model.
- Auth, multi-tenancy, billing.
- PDF export (HTML is enough).
- Pre-install gatekeeper installer (the shipped Android app audits installed apps only;
  see doc 05).
- Full native (`.so`) decompilation.
- Play Store upload.

---

## 2. 48-hour plan

Assumes 2–3 people. Solo: cut items 6–7 to one LLM pass and skip the chat.

| Block | Work | Done when |
|---|---|---|
| **H0–2** | Repo skeleton, pyproject, CLI stub, sample APKs, hashing/zip guards | `anbu scan` prints identity |
| **H2–8** | Manifest + cert + DEX extraction, JSON dump of classes/strings/xrefs | Can inspect any APK as JSON |
| **H8–14** | Rule packs + severity data + combo engine | Score works with **no** LLM |
| **H14–18** | Class ranker + code slicing (smali or jadx output) | Top-20 list looks plausible on 2 apps |
| **H18–26** | LLM client, prompts, schemas, evidence verifier | Findings appear with verified quotes |
| **H26–32** | Scorer fusion + bands + confidence/coverage | One number, defensible |
| **H32–38** | HTML report + plain-language summary | Screenshot-ready report |
| **H38–44** | Eval on 30 apps, fix top 3 failure modes | Metrics recorded |
| **H44–48** | Demo rehearsal, fallback fixtures, README | 5-minute demo runs twice |

**Parallelisation:** person A owns ingest/extract/rank; person B owns rules/score/report;
person C owns LLM/verifier/eval. Freeze interfaces at H8 (`analysis.json` schema) so the
three can work independently.

---

## 3. Week-by-week roadmap

### Week 1 — working single-app pipeline
- Steps 1–10 above, CLI only.
- Prompt-injection fixture and evidence verification in CI.
- Baseline eval report committed as `docs/eval-baseline.md`.

### Week 2 — service and analyst UX
- FastAPI: `POST /scan` (multipart), `GET /scans/{id}`, async worker (RQ/Celery).
- Postgres for reports, object store for artifacts.
- Report caching by APK SHA-256 (identical uploads cost zero tokens).
- Chat endpoint over a stored report (RAG on the same chunks).
- Docker Compose; no auth yet, bind to localhost.

### Week 3 — depth
- Native metadata: `readelf`/`strings`/JNI registration detection.
- Packer handling: APKiD + explicit "unpacking needed" path.
- Split APK/AAB merge via `bundletool`.
- Taint-lite source→sink flows.
- `jadx --deobf` on ranked classes; identifier-renaming summaries.
- VirusTotal hash lookup with cached results.

### Week 4 — trust and scale
- Calibration (Platt/isotonic), Brier/ECE in eval.
- ML baseline (logistic regression / LightGBM on features) compared against rules.
- Batch mode + CI gate (`--fail-on high`).
- HTML report polish, per-finding feedback ("agree/disagree") stored for future tuning.
- Threat model + disclosure policy.

### Phase 3 — only if justified
- Dynamic sandbox (MobSF or emulator + Frida + mitmproxy) triggered on suspicion.
- Gatekeeper installer, new-app inbox, and background scanning (doc 05; the post-install
  auditor already ships).
- Family clustering via embeddings of behaviour summaries.
- Auto-generated detection rules from findings (reviewed by a human).

---

## 4. Demo script (5 minutes)

1. **Problem (30 s):** "A user in India receives a loan app APK on WhatsApp. Permissions
   look normal. What does it actually do?"
2. **Benign app (60 s):** scan a real open-source app → score ~10, show permissions,
   show "no malicious signals", note coverage 94%.
3. **Malicious app (120 s):** scan a labelled sample → score 88, band critical.
   Open three findings: SMS receiver → Telegram endpoint; accessibility service;
   `DexClassLoader` from assets. Each shows the quoted smali line and MITRE mapping.
4. **The "why" (60 s):** ask the report chat "does it steal OTPs?" → answer cites the
   receiver and the forwarding call.
5. **Honesty (30 s):** scan a packed sample → score low but **coverage 18% →
   inconclusive**, with "dynamic analysis required". This is the moment judges trust you.
6. **Close (30 s):** architecture slide, eval numbers, "what we'd add next".

**Fallback:** pre-generated reports for all demo apps in `samples/expected/`, so a dead
API key or slow network cannot kill the demo. Show live only what is reliable.

---

## 5. Budgets

| Item | Target | Notes |
|---|---|---|
| Scan latency (static) | < 10 s p50, < 30 s p95 | jadx on subsets only |
| LLM latency | < 30 s | cap output tokens; stream to UI |
| Tokens/app | 40k–150k input | top 20–30 classes, 2–4k tokens each |
| Cost/app | < $0.10 | depends on model; cache by hash |
| Memory | < 1.5 GB | this machine has ~1.5 GB free |
| Report size | < 2 MB HTML | inline CSS, no external CDN |

Set a hard per-scan token budget in code. A runaway agent loop is the easiest way to
turn a demo into a bill.

---

## 6. Team split and risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| jadx/JVM missing on dev box | high here | androguard-only MVP; smali slices are enough |
| LLM hallucinated evidence | high | verifier gate; drop unverified findings |
| Packed samples tank the demo | high | coverage/inconclusive path; pick unpacked samples |
| Emulator rabbit hole | high | do not build dynamic in MVP |
| Token cost blowup | medium | budget cap, hash cache, top-K selection |
| Legal exposure from samples | medium | isolated lab, never commit, doc 04 rules |
| "Safe" claim backlash | medium | wording: "no known malicious signals" |

Roles for three people: **pipeline engineer** (ingest/extract/rank), **detection
engineer** (rules/score/eval), **AI engineer** (prompts/verifier/report/chat). Solo
founders should do pipeline + rules first, then add AI; a rule-based score with a good
report already demos well.

---

## 7. Definition of done

- [ ] `anbu scan` works on 30 diverse APKs without crashing.
- [ ] Every finding in the report has a verified artifact quote.
- [ ] Score is reproducible: same APK + same rules + same model = same number.
- [ ] Packed/low-coverage apps are labelled inconclusive, never "safe".
- [ ] Prompt-injection fixture is ignored by the pipeline.
- [ ] Eval metrics (recall, FPR, evidence precision, latency) are published in-repo.
- [ ] No sample APK or extracted code is committed.
