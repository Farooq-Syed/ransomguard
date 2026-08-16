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
benign sessions (document edits, downloads, archive noise) and ransomware sessions (mass
high-entropy rewrites, extension renames, note drops, shadow-copy deletion), generated in
`tools/simulate.py`.

Run the tests yourself:

```bash
python run_v1_test.py --n-benign 60 --n-ransom 60 --seed 1337
python train_v2.py
python run_v2_test.py --seed 1337
python run_compare.py --seed 1337
```

### Results (seed 1337, 60 benign + 60 ransomware sessions)

| Metric | v1 (heuristics) | v2 (ML) |
|---|---|---|
| Detection rate (attacks caught) | 100.0% | <fill in> |
| False-positive rate (benign flagged) | 0.0% | <fill in> |
| Mean latency to first alert | 0 steps | <fill in> |

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
