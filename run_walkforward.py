"""Walk-forward (temporal) evaluation of v1 vs v2.

A time-ordered corpus is split into buckets with an *evolving* distribution:
early buckets hold classic/stealth attacks at low noise; later buckets
introduce novel-ext attacks, entropy-evading wipers, and higher benign noise —
i.e. genuinely unseen "future" behaviour.

For each fold we train v2 only on buckets in the past and test on the next
(future) bucket; v1 is rule-based so it is just scored on the same bucket.
This measures temporal generalization, not in-sample fit.

Usage: python run_walkforward.py [--seed 7] [--buckets 10] [--bucket-size 12]
"""
from __future__ import annotations

import argparse
import os
import tempfile

from ransomguard_ml.train import train_and_save
from tools.harness import evaluate_v1, evaluate_v2, make_test_config
from tools.results import line_chart, save_json
from tools.simulate import build_timeline

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = os.path.join(ROOT, "results")


def make_schedule(n_buckets: int):
    early = {"styles": ["classic", "stealth"], "noise": 0.15}
    mid = {"styles": ["classic", "stealth", "novel_ext"], "noise": 0.3}
    late = {"styles": ["classic", "stealth", "novel_ext", "wiper"], "noise": 0.5}
    schedule = []
    third = max(1, n_buckets // 3)
    for b in range(n_buckets):
        if b < third:
            schedule.append(early)
        elif b < 2 * third:
            schedule.append(mid)
        else:
            schedule.append(late)
    return schedule


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--buckets", type=int, default=10)
    ap.add_argument("--bucket-size", type=int, default=12)
    ap.add_argument("--n-files", type=int, default=35)
    ap.add_argument("--n-windows", type=int, default=7)
    ap.add_argument("--train-window", type=int, default=5)
    ap.add_argument("--step", type=int, default=2)
    ap.add_argument("--tag", type=str, default="")
    args = ap.parse_args()
    os.makedirs(RESULT_DIR, exist_ok=True)
    tag = f"_{args.tag}" if args.tag else ""

    tmp = tempfile.mkdtemp(prefix="rg_wf_")
    schedule = make_schedule(args.buckets)
    buckets = build_timeline(args.buckets, args.bucket_size, args.seed, tmp, schedule,
                             n_files=args.n_files, n_windows=args.n_windows)

    def evaluate(sessions):
        r1, r2 = [], []
        for s in sessions:
            cfg = make_test_config(s["sandbox"].root, "", low_rate=False)
            r1.append(evaluate_v1(s, cfg))
            r2.append(evaluate_v2(s, payload, cfg))
        n_r = sum(1 for r in r1 if r["kind"] == "ransomware")
        n_b = sum(1 for r in r1 if r["kind"] == "benign")
        if n_r == 0 or n_b == 0:
            raise ValueError("Each walk-forward test bucket must contain ransomware and benign sessions.")
        det1_count = sum(1 for r in r1 if r["detected"])
        det2_count = sum(1 for r in r2 if r["detected"])
        fp1_count = sum(1 for r in r1 if r["false_alarm"])
        fp2_count = sum(1 for r in r2 if r["false_alarm"])
        return {
            "det1": det1_count / n_r,
            "det2": det2_count / n_r,
            "fp1": fp1_count / n_b,
            "fp2": fp2_count / n_b,
            "ransomware_sessions": n_r,
            "benign_sessions": n_b,
            "v1_detected_sessions": det1_count,
            "v2_detected_sessions": det2_count,
            "v1_false_alarm_sessions": fp1_count,
            "v2_false_alarm_sessions": fp2_count,
        }

    folds = []
    test_bucket = args.train_window
    payload = None
    while test_bucket < args.buckets:
        train_sessions = [s for b in range(test_bucket - args.train_window, test_bucket)
                          for s in buckets[b]["sessions"]]
        test_sessions = buckets[test_bucket]["sessions"]
        print(f"\n== Fold: train buckets [{test_bucket - args.train_window}, {test_bucket}) "
              f"-> test bucket {test_bucket} ==")
        print(f"  training on {len(train_sessions)} sessions...")
        payload = train_and_save(train_sessions, os.path.join(tmp, f"model_fold_{test_bucket}.pkl"))
        m = evaluate(test_sessions)
        folds.append({
            "fold": test_bucket,
            "test_bucket_styles": schedule[test_bucket]["styles"],
            "test_noise": schedule[test_bucket]["noise"],
            "v1_detection": round(m["det1"], 3),
            "v2_detection": round(m["det2"], 3),
            "v1_fp": round(m["fp1"], 3),
            "v2_fp": round(m["fp2"], 3),
            "ransomware_sessions": m["ransomware_sessions"],
            "benign_sessions": m["benign_sessions"],
            "v1_detected_sessions": m["v1_detected_sessions"],
            "v2_detected_sessions": m["v2_detected_sessions"],
            "v1_false_alarm_sessions": m["v1_false_alarm_sessions"],
            "v2_false_alarm_sessions": m["v2_false_alarm_sessions"],
        })
        print(f"  v1 det={m['det1'] * 100:.0f}% fp={m['fp1'] * 100:.0f}% | "
              f"v2 det={m['det2'] * 100:.0f}% fp={m['fp2'] * 100:.0f}%")
        test_bucket += args.step

    print("\n=== WALK-FORWARD (temporal generalization) ===")
    print(f"{'fold(test)':<12} {'styles':<30} {'v1 det':>7} {'v2 det':>7} {'v1 FP':>6} {'v2 FP':>6}")
    for f in folds:
        styles = "+".join(f["test_bucket_styles"])
        print(f"{f['fold']:<12} {styles:<30} {f['v1_detection'] * 100:>6.0f}% {f['v2_detection'] * 100:>6.0f}% "
              f"{f['v1_fp'] * 100:>5.0f}% {f['v2_fp'] * 100:>5.0f}%")

    save_json({"schedule": schedule, "seed": args.seed, "folds": folds},
              os.path.join(RESULT_DIR, f"walkforward{tag}.json"))
    labels = [f["fold"] for f in folds]
    line_chart(labels, {"v1 detection": [f["v1_detection"] for f in folds],
                        "v2 detection": [f["v2_detection"] for f in folds]},
               os.path.join(RESULT_DIR, f"walkforward_det{tag}.png"),
               "Walk-forward: detection rate on future buckets (never seen in training)",
               "detection rate")
    line_chart(labels, {"v1 FP": [f["v1_fp"] for f in folds],
                        "v2 FP": [f["v2_fp"] for f in folds]},
               os.path.join(RESULT_DIR, f"walkforward_fp{tag}.png"),
               "Walk-forward: false-positive rate on future buckets", "false-positive rate", ylim=(-0.02, 1.02))
    print(f"\nSaved results to {RESULT_DIR}/walkforward{tag}.json, walkforward_det{tag}.png, walkforward_fp{tag}.png")


if __name__ == "__main__":
    main()
