# Roadmap / Future plans

Prioritised by impact. Each item lists *why*, a concrete *approach*, and an *acceptance criterion*
so progress is measurable. Phases roughly reflect dependency order, not strict sequential work.

---

## Phase 1 — Ground the evaluation in reality (highest priority)

The strongest numbers we have come from a self-consistent simulator. Before trusting them in
production, the evaluation itself must be re-grounded.

- **Real file-activity corpus.** Collect labelled benign traces (normal user sessions: editing,
  sync, builds, backups, indexer churn) and score v1/v2 against them.
  - Approach: ship an eval harness that consumes a directory of real traces (JSON event streams) in
    the same batch format the engines already consume; add a `--from-traces` path.
  - Acceptance: report detection/FP on ≥ 5 real machines' benign activity with no simulator
    involvement.
- **Ransomware-family replay.** Replay captures/samples of real families (LockBit, Ryuk, Conti,
  REvil, Akira, BlackCat, wipers like Shamoon/NotPetya) inside an isolated sandbox/VM and score both
  engines against known ground truth.
  - Acceptance: per-family detection-rate and latency table in `results/`.
- **Cross-validation on held-out years/waves** (temporal split of any real corpus) so "future"
  genuinely means unseen time.

## Phase 2 — Close the known detection gaps

- **USN Journal incremental indexing (Windows).** The snapshot-diff engine can miss files created,
  encrypted, renamed, and deleted between two scans. Read the NTFS USN journal between baselines for
  a complete, race-free change set.
  - Acceptance: a file cycled through create→encrypt→delete within one scan interval is still
    reported.
- **Real process attribution (ETW/Sysmon).** Open-handle matching (`psutil.open_files()`) misses fast
  open/close. Use ETW file-op events (elevated) to attribute each write to a PID reliably.
  - Acceptance: writer PID/name reported for >95% of flagged files on Windows.
- **Container-aware content analysis.** Reduce structural false positives on legitimate high-entropy
  data (archives, disk images, DBs, BitLocker) by detecting known container magic + expected
  structure instead of raw entropy alone.
  - Acceptance: a folder of valid `.zip`/`.7z`/`.vmdk`/`.sqlite` edits no longer triggers HIGH.
- **Evasion hardening.**
  - Decoys in hidden/rarely-visited paths (AppData, drive roots, empty folders) as well as Documents.
  - Cross-file entropy correlation (encryption raises entropy *across* many files at once — a
    stronger signal than any single file).
  - Detect bulk directory enumeration (handle-opens/sec) as a pre-encryption warning.
  - Self-healing honeypots that re-arm themselves after deletion.
  - Acceptance: targeted tests where the simulated attacker avoids every single-file heuristic still
    trip at least one correlated/multi-signal rule.

## Phase 3 — ML lifecycle and robustness

- **Continual / online learning with drift gating.** The frozen model is the source of the
  walk-forward FP instability. Add automatic retraining when the drift monitor trips, using only
  operator-confirmed data.
  - Acceptance: the fold-9 (seed 7) 5/5 benign false-alarm failure self-heals within one retrain cycle.
- **Temporal sequence modelling.** Per-window classification ignores ramp-up patterns. Evaluate an
  LSTM/GRU (or a feature-streak encoder) over consecutive windows for slow-trickle attacks.
  - Acceptance: a 1-file/window slow attack is flagged by streak of anomalous-but-below-threshold
    windows.
- **Threshold calibration on real data + explicit FP budget.** Move thresholds from fixed values to a
  configurable false-positive-per-week budget.
- **Proper SHAP integration** (replace the lightweight LIME) and alert triage ranking by expected
  impact.

## Phase 4 — Response, recovery, integration

- **Backup-integrity verification.** On `CRITICAL`, verify that VSS/backup snapshots still exist and
  are mountable; raise severity if the recovery path is also compromised.
- **SIEM / EDR integration.** Structured alerts (CEF already supported) → syslog, and a webhook
  action chain to EDR/XDR APIs for automated containment.
- **Recovery workflow.** End-to-end restore from quarantine + snapshot store, with a confirmation
  gate for false positives.
- **Network & lateral movement.** Actively watch mapped drives/SMB shares; flag mass writes over the
  network and mass deletions of `.bak`/`.vmdk` (backup destruction).

## Phase 5 — Scale and productisation

- **Incremental scanning** (USN journal + per-directory priority), so large trees don't rescan every
  interval.
- **Packaging:** Windows service / systemd unit, log rotation, `--once` for cron.
- **Telemetry dashboard** (alert history, scores, drift, honeypot status).
- **False-positive feedback loop** for the allow-list and ML thresholds.
- **Cross-platform parity** (Linux inotify, macOS FSEvents) with the same feature set.

---

## Immediate next steps (suggested order)

1. Build the trace-replay eval harness (`--from-traces`) and gather one real benign corpus.
2. USN Journal change enumeration on Windows.
3. Online retraining gated by the drift monitor.
4. Container-aware entropy to cut structural FPs.

Each is independent enough to be a standalone PR/commit.
