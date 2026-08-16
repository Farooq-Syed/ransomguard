# RansomGuard

Early-warning ransomware detector for a single machine. Continuously watches your data files,
system-critical files, decoy "canary" files, running processes and system resources, and raises
alerts when behaviour matches how ransomware works — before the whole disk is encrypted.

Two detection engines, comparable side by side:

| Version | Approach | Status |
|---|---|---|
| **v1** | Rule/heuristic scoring engine | Tested: 100% detection, 0% false positives (120 simulated sessions) |
| **v2** | Machine-learning detector (RandomForest, trained on synthetic benign/ransomware window features) | Trained + tested, results below |

---

## Why these files? (research)

Ransomware follows a very predictable playbook (MITRE ATT&CK [T1486](https://attack.mitre.org/techniques/T1486/)
"Data Encrypted for Impact"). It targets **common user files** — Office documents, PDFs, images,
videos, audio, text, source code — while typically **avoiding** executables and system DLLs so the
OS stays alive to keep running. It then:

1. Rewrites files in place with an encrypted (high-entropy) stream
2. Renames files, appending a marker extension (`.lockbit`, `.ryuk`, `.conti`, `.enc`, `.locked`, ...)
3. Drops ransom notes (`README_RESTORE.txt`, `RyukReadMe.txt`, `!read_me_medusa!!.txt`, ...)
4. Deletes volume shadow copies (`vssadmin delete shadows /all /quiet`)
5. Works fast — hundreds of files per minute

### Prioritised target list (used for early-warning configuration)

| Priority | What ransomware wants | Examples |
|---|---|---|
| **95** | Private keys, wallets, credentials | `~/.ssh`, `~/.gnupg`, `~/.aws`, `.pem`, `.pfx`, `.jks`, `.wallet` |
| **90+** | Critical OS state | `hosts`, registry hives (`SAM`, `SYSTEM`, `SECURITY`), `BCD` boot config |
| **70** | Documents & Office files | `.docx`, `.xlsx`, `.pptx`, `.pdf`, `.rtf`, `.odt` |
| **55–70** | Photos & media | `.jpg`, `.png`, `.raw`, `.mp4`, `.mkv`, `.mov` |
| **55** | Databases | `.sql`, `.sqlite`, `.accdb`, `.mdb`, `.db` |
| **50–60** | Backups & archives | `.bak`, `.zip`, `.rar`, `.7z`, `.vmdk`, `.vhdx`, `.ost`, `.pst` |
| **40** | Source code & config | `.py`, `.java`, `.js`, `.yaml`, `.env`, `.json` |

The core principle for "early precautions": **watch the files that are rarely touched**. A file that
sat untouched for 30+ days suddenly being rewritten with high-entropy content is a far stronger
signal than a daily-edited spreadsheet changing.

---

## Detection signals (v1 heuristic engine)

Every scan window produces a weighted suspicion score. `HIGH`+ alerts are only raised when at least
one **strong signal** is present, to avoid false alarms on normal use:

- **High file entropy** (encrypted data is statistically random) — strong
- **File magic-byte change** (a PDF that is no longer a PDF) — strong
- **Extension churn / mass renames** to ransom-style extensions — strong
- **Ransom note creation** (name + location heuristics) — strong
- **Honeypot / canary file touched** — strong (nothing legitimate ever touches these)
- **Shadow-copy deletion** via `vssadmin`/`wmic`/`bcdedit` — strong
- **Suspicious process** from `Temp`/`AppData` running known crypto utilities — strong
- **Mass modification rate** (hundreds of files/min) — strong
- Age of file + rarity of the path — weights the score per path priority
- CPU / memory / disk-write bursts — corroborating signals

On `CRITICAL`/`PANDEMIC` the detector can optionally **quarantine** the flagged files and (if
`auto_freeze`) suspend the offending process.

---

## Quick start

```bash
pip install -r requirements.txt

# 1. Tune the watch list to your machine (paths, priorities, honeypot dirs)
python main.py --check-config

# 2. Plant decoy canary files in the monitored folders
python main.py --setup-honeypots

# 3. See what your setup actually watches (prioritised inventory)
python main.py --scan-once

# 4. Run the continuous monitor
python main.py
```

Other commands:

```bash
python main.py --freeze-now        # emergency: suspend suspicious processes
python main.py --remove-honeypots  # clean up canaries
```

### v2 (ML)

```bash
python train_v2.py --n-benign 400 --n-ransom 400 --seed 42   # train a fresh model
python -m ransomguard_ml.monitor --model models/v2_model.pkl # run the ML monitor
```

---

## Evaluation

Both versions are tested on **identical synthetic sessions** that replay real filesystem activity:
benign sessions (document edits, downloads, archive noise, folder-copy bursts) and ransomware
sessions — both "classic" (renames, ransom notes, shadow-copy deletion) and "stealth" (pure
high-entropy rewrites, no notes/renames/process traces) — generated in `tools/simulate.py`.

Run the tests yourself:

```bash
python run_v1_test.py --n-benign 60 --n-ransom 60 --seed 1337
python train_v2.py
python run_v2_test.py --seed 1337
python run_compare.py --seed 1337            # clean scenario
python run_compare.py --seed 1337 --prod-rates   # noisy benign + stealth
```

### v2 model validation (20% holdout windows, 400 benign + 400 ransomware training sessions)

accuracy 1.000 · precision 1.000 · recall 1.000 · ROC AUC 1.000

The model's top learned features mirror v1's heuristics — a useful sanity check that the rules
encode real signal: `max_entropy_mod`, `n_high_value_mod`, `mean_entropy_mod`, `n_modified`,
`n_target_mod`, `n_crypto_procs`.

### Head-to-head results (60 benign + 60 ransomware sessions each, seed 1337)

**Clean scenario** (clean benign + classic attacks, default thresholds) — both engines:

| Metric | v1 (heuristics) | v2 (ML) |
|---|---|---|
| Detection rate | 100.0% | 100.0% |
| False-positive rate | 0.0% | 0.0% |
| Mean latency | 0 steps | 0 steps |

**Stress scenario** (noisy benign incl. folder-copy bursts, 30% stealth attacks):

*Aggressive/test rate thresholds (warn 25/min, critical 60/min)*

| Metric | v1 (heuristics) | v2 (ML) |
|---|---|---|
| Detection rate (classic + stealth) | 100.0% (60/60) | 100.0% (60/60) |
| False-positive rate | **91.7%** (55/60) | **0.0%** (0/60) |

*Production-like rate thresholds (warn 100/min, critical 600/min)*

| Metric | v1 (heuristics) | v2 (ML) |
|---|---|---|
| Detection rate | 100.0% | 100.0% |
| False-positive rate | 0.0% | 0.0% |

### What the comparison shows

- **Detection power is equal**: both catch every attack, stealth included, at the first window.
  The simulated encryption always produces the entropy/magic signals v1 was designed around, so
  the rules already capture the same signal the model learns.
- **v2 is more precise under noisy-but-benign activity**: v1's mass-modification heuristic can't
  tell a legitimate folder copy (50–90 new files in a window) from mass encryption, so it fires
  at aggressive thresholds; v2, having seen such bursts in training, stays quiet.
- **Both are instant** (0-step latency) on these workloads.

Practical takeaway: run **both** engines side by side — v1 gives explainable rule-based alerts and
emergency actions (quarantine/freeze); v2 adds ML-grounded precision that tolerates noisy benign
environments without threshold hand-tuning.

---

## Configuration

Everything lives in `config.json`: watch directories with per-path priorities, honeypot locations,
entropy threshold, modification-rate thresholds, ransom-note patterns, process lists, resource
thresholds, webhook URL (Slack/Teams/Discord compatible JSON POST), and emergency actions.

---

## Project layout

```
ransomguard/           v1 package (config, filesystem/process/resource monitors,
                       honeypots, detector, alerter)
ransomguard_ml/        v2 ML package (feature extraction, runtime monitor)
tools/                 simulation + evaluation harness (identical input for both versions)
main.py                v1 entry point
train_v2.py            v2 training
run_v1_test.py         v1 evaluation
run_v2_test.py         v2 evaluation
run_compare.py         head-to-head comparison
```

---

## Disclaimer

This is a detection/early-warning tool, not a firewall or EDR replacement. It complements backups
(keep them offline), endpoint protection, and least-privilege policies. It is provided as-is;
test and tune it on your own machine before relying on it.
