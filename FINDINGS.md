# Findings

Consolidated results from every evaluation in the repo. All numbers are reproducible via the
scripts listed. See `README.md` for how to run them and `ROADMAP.md` for what's next.

## Evaluation summary

| Evaluation | What it tests | Outcome |
|---|---|---|
| Unit tests (`pytest tests`) | entropy, magic, scoring, allow-list, silent-tamper, honeypots, features | 19/19 pass |
| Standard v1 / v2 suite (60+60, seed 1337) | trained distribution, classic + stealth | 100% detection, 0% FP |
| Compare — aggressive thresholds | noisy benign + bursts | v1 FP **91.7%**, v2 FP **0%** |
| Compare — production thresholds | same, realistic rate limits | both 0% FP |
| Near-real (seeds 2024/2025) | shifted distribution + novel attack styles | both 100% detection on all styles, 0% FP |
| Walk-forward (canonical seed 7) | future buckets, evolving distribution | both 100% detection; v1 FP stable 0%, v2 reaches 5/5 benign false alarms in fold 9 |

## Key findings

1. **Both engines are excellent on the trained and on near-real shifted workloads.** 100% detection
   of classic, stealth, and novel-ext attacks at 0-step latency, with 0% false positives on the
   standard distribution. The ML top features converge on the same signals v1 encodes manually
   (max/mean entropy, high-value-file modification, crypto-tool processes) — a sanity check that the
   rules and the learned model agree.

2. **v2 is more precise on noisy-but-benign activity — when its training matches that noise.**
   At aggressive rate thresholds, v1's mass-modification heuristic cannot tell a folder-copy burst
   from mass encryption (91.7% FP); v2, having seen bursts in training, stays at 0%.

3. **v1 is more stable over time; v2 requires drift response.** The canonical walk-forward rerun shows
   v2's false-positive rate on *future* noisy-benign windows can fail catastrophically — 5/5 benign
   sessions alerted in fold 9 after the distribution shift, while v1 remained at 0/5 false alarms.
   v1's deterministic rules remained at 0% FP. This is an internal example of ML
   distribution-shift/staleness and is the strongest argument for testing drift-triggered
   retraining, and for keeping v1 as a stable baseline. Retraining recovery is a planned
   experiment, not a result claimed by the canonical run.

4. **Entropy is necessary but not sufficient.** The entropy-evading `wiper` variant (zero-fills,
   no renames, no notes) is caught — but by **honeypot canaries, mass deletions, and process
   signals**, not by content analysis. A wiper that also removes decoys and throttles deletions
   would very likely slip through both engines. Content-aware ciphertext/container analysis and
   behavioral confirmation are the real fixes.

5. **Honeypots are the highest-leverage single signal.** A canary hit is +120 and near-certain.
   Randomised realistic names (no `~canary_` prefix) prevent fingerprinting; bait canaries
   (pre-partially-encrypted) catch malware that skips "already encrypted" files. Keep planting them,
   in the places an attacker is most likely to hit first (Documents, Desktop, shares, key dirs).

6. **Known blind spots** (honest limits, all documented as accepted risk or roadmap items):
   - Wipers that avoid decoys/deletions (see #4).
   - mtime-preserving rewrites of files that are **not** in the content-hash tracked set
     (tracked set is bounded by `hash_track_max_files`).
   - Low-and-slow attacks that stay under every rate threshold.
   - An informed attacker who knows the tool (fingerprints the watchers, throttles, deletes decoys).
   - Anything on network shares when `watch_mapped_drives` is off.

7. **The biggest caveat: the test corpus is synthetic.** Training and evaluation share the same
   simulator, so strong numbers partly measure self-consistency. The near-real/walk-forward runs
   mitigate this by shifting seeds, noise, and attack styles across time, but a corpus of real
   file-activity traces and known ransomware-family replays is the necessary next step before
   trusting the numbers in production.

## Number tables

### Near-real (novel styles, seeds 2024 & 2025)

| style | v1 | v2 |
|---|---|---|
| classic | 100% | 100% |
| stealth | 100% | 100% |
| novel_ext (new exts/notes) | 100% | 100% |
| wiper (entropy-evading) | 100% | 100% |
| benign FP rate | 0% | 0% |

### Walk-forward (future buckets; v2 retrained on past buckets only)

| future bucket | styles | v1 det | v2 det | v1 FP | v2 FP |
|---|---|---|---|---|---|
| 5 | + novel_ext | 100% | 100% | 0% | 0% |
| 7 | + wiper | 100% | 100% | 0% | 0% |
| 9 | + wiper, heaviest noise | 7/7 | 7/7 | 0/5 | 5/5 |

The fold denominators are small, so 100% is not a precise population estimate. The result is still
an unambiguous internal failure case: every benign session in that held-forward bucket alerted.

Charts saved under `results/` (`nearreal*.png`, `walkforward_det*.png`, `walkforward_fp*.png`).
