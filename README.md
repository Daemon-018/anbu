# ANBU 🥷

**A safety checker for Android apps. Give it an `.apk` file, get a score out of 100
and a list of exactly what looks sneaky.**

ANBU is named after the ANBU black-ops squad in Naruto: a small, quiet team that finds
out what is really going on before anything bad happens.

---

## What does it do? 🕵️

Think of an APK like a locked backpack. You can't see inside, and someone is asking you
to carry it. ANBU opens the backpack **without running anything inside it**, looks at
all the pockets, and tells you:

* what the app is allowed to do (read your texts? see your contacts? draw on top of
  other apps?),
* which parts of the code look like trouble,
* a score from **0 to 100**,
* and the exact lines that made it say so — no "trust me bro".

It never says an app is "safe". The most it will say is *"I found no known bad stuff
in the parts I could read."* That is a big difference, and it is on purpose.

---

## The score, in one table 🎯

| Score | What it means |
|---|---|
| 0–19 | Nothing bad found. Still not a promise. |
| 20–44 | A few risky powers, but no clear bad plan. |
| 45–69 | Behaviours malware uses a lot. Be careful. |
| 70–84 | Strong signs of bad behaviour. Don't install. |
| 85–100 | Several bad things working together. Stay away. |

If the app hides its code (packers do that), ANBU says **"inconclusive"** instead of
pretending everything is fine. A low score on a locked box is not good news.

---

## Try it in 3 steps 🚀

**1. Install it** (you need Python 3.10 or newer):

```bash
pipx install "git+https://github.com/Daemon-018/anbu.git"
```

No pipx? This also works:

```bash
git clone https://github.com/Daemon-018/anbu.git
cd anbu
python -m pip install -e .
```

**2. Scan an app you are allowed to scan:**

```bash
anbu scan my-app.apk --out out/
```

You get two files:

* `out/my-app.json` — the full report, for programs,
* `out/my-app.html` — a pretty report, open it in any browser.

**3. Read the answer.** The terminal shows the highlights:

```text
Package : org.example.app (Example)
Score   : 12/100 - likely benign (confidence: high, coverage: 100%)
Top findings:
  [medium  ] ID-07 Exports components without protecting them
```

### No APK handy? Use the demo 📦

The [v1.0.0 release](https://github.com/Daemon-018/anbu/releases/tag/v1.0.0) includes
`anbu-demo-sample.apk`. It is a **fake, harmless** app built by the test suite to show
off every check. Unzip it, scan it, and you should see a big red **100/100** with three
attack patterns (`BANKER`, `OTP-STEALER`, `SPYWARE`).

You can also build it yourself, no Android tools needed:

```bash
python tests/fixtures/apk_builder.py out/demo.apk
anbu scan out/demo.apk --out out/
```

---

## What ANBU is not 🙅

* **It is not an app on your phone.** ANBU is a command-line tool that runs on a
  computer. (An on-device version is only a design idea for now — see `docs/05`.)
* **It does not run the APK.** Nothing inside it gets executed. Ever.
* **It cannot see everything.** Code fetched from the internet later, or hidden inside
  native `.so` files, stays invisible. "No bad signals" ≠ "safe".
* **It is not a judge.** A score is a hint for a human, not a legal verdict.

⚠️ Only scan APKs you own or have permission to inspect.

---

## Cool extras 🧰

**Send the most suspicious code to an AI helper** (optional, off by default). The AI can
add findings, but every quote it gives is checked against the real file first — invented
quotes are thrown away, and it is never allowed to set the score.

```bash
export ANBU_LLM_BASE_URL=https://your-host/v1
export ANBU_LLM_MODEL=some-chat-model
export ANBU_LLM_API_KEY=...        # not needed for a local server
anbu scan my-app.apk --llm --out out/
```

**Use it in a robot / CI check** — fail the build when something looks bad:

```bash
anbu scan my-app.apk --out out/ --fail-on high   # exit code 3 when score reaches "high"
```

---

## For grown-up developers 👩‍💻

ANBU is pure Python. The only runtime dependency is `androguard`, so it works without a
JVM, Android SDK, or emulator.

| Part | File | Job |
|---|---|---|
| Ingest | `src/anbu/ingest.py` | zip safety checks, SHA-256, refuses broken archives |
| Extract | `src/anbu/extract.py` | manifest, certificates, DEX facts, strings, URLs, packer hints |
| Rules | `src/anbu/rules.py` + `data/rules.json` | 37 declarative rules and 7 named combos |
| Ranker | `src/anbu/rank.py` | picks the classes worth reading and slices them |
| AI pass | `src/anbu/interpret/` | schema-constrained prompt, injection guard, evidence verifier |
| Score | `src/anbu/score.py` | deterministic math, bands, coverage honesty |
| Report | `src/anbu/report.py` | JSON and one self-contained HTML file |

Design rule: **the model never writes the number.** Findings go in, the scorer computes
the score.

Run the checks:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

The suite covers the rule pack, ranking, the evidence gate, scoring, report escaping, a
real benign APK when one is present, and a synthetic malicious APK built offline.

Deeper documents live in [`docs/`](docs/): approaches, risk scoring, roadmap, safety and
legal notes, the on-device idea, and an auditor screen spec.

---

## License 📄

MIT. See [LICENSE](LICENSE).
