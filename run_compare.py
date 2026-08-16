"""Head-to-head comparison: v1 (heuristics) vs v2 (ML) on identical sessions.

Usage: python run_compare.py [--model models/v2_model.pkl] [--seed 1337]
"""
from __future__ import annotations

import argparse
import pickle
import tempfile

from tools.harness import evaluate_v1, evaluate_v2, make_sessions, summarize_results


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=str, default="models/v2_model.pkl")
    ap.add_argument("--n-benign", type=int, default=60)
    ap.add_argument("--n-ransom", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-files", type=int, default=40)
    ap.add_argument("--n-windows", type=int, default=8)
    args = ap.parse_args()

    with open(args.model, "rb") as fh:
        payload = pickle.load(fh)
    model, feature_names = payload["model"], payload["feature_names"]

    tmp = tempfile.mkdtemp(prefix="rg_cmp_")
    sessions = make_sessions(args.n_benign, args.n_ransom, args.seed, tmp,
                             n_files=args.n_files, n_windows=args.n_windows)
    print(f"Comparing on {len(sessions)} sessions (seed {args.seed})...\n")

    r1, r2 = [], []
    for i, s in enumerate(sessions):
        r1.append(evaluate_v1(s))
        r2.append(evaluate_v2(s, model, feature_names))
        if (i + 1) % 30 == 0:
            print(f"  evaluated {i + 1}/{len(sessions)} sessions")

    m1, m2 = summarize_results(r1), summarize_results(r2)

    def row(label, v1, v2, fmt="{:.1f}%", best="low"):
        v1s = fmt.format(v1)
        v2s = fmt.format(v2)
        mark = ""
        if best == "low":
            mark = " <-" if v2 < v1 else (" <-" if v1 < v2 else "")
        else:
            mark = " <-" if v2 > v1 else (" <-" if v1 > v2 else "")
        print(f"{label:<26} v1 {v1s:>8}    v2 {v2s:>8}{mark}")

    print("metric                      v1         v2")
    row("Detection rate (TPR)", m1["detection_rate"], m2["detection_rate"], best="high")
    row("False-positive rate", m1["false_positive_rate"], m2["false_positive_rate"], best="low")
    row("TP / FN", m1["tp"], m2["tp"], fmt="{:.0f} / {:.0f}")
    row("FP / TN", m1["fp"], m2["fp"], fmt="{:.0f} / {:.0f}")
    lat1 = m1["latency_mean_steps"]
    lat2 = m2["latency_mean_steps"]
    print(f"{'Mean latency to detect':<26} v1 {str(lat1):>8}    v2 {str(lat2):>8}   (steps)")

    print("\n--- verdict ---")
    if m2["detection_rate"] > m1["detection_rate"]:
        verdict = "v2 (ML) catches a higher share of attacks"
    elif m1["detection_rate"] > m2["detection_rate"]:
        verdict = "v1 (heuristics) catches a higher share of attacks"
    else:
        verdict = "Both detect the same share of attacks"
    if m2["false_positive_rate"] < m1["false_positive_rate"]:
        fp_part = " and is more precise (fewer false alarms)"
    else:
        fp_part = " but has more false alarms on benign activity"
    print(verdict + fp_part + ".")
    if m2["latency_mean_steps"] is not None and m1["latency_mean_steps"] is not None:
        if m2["latency_mean_steps"] < m1["latency_mean_steps"]:
            print("v2 flags the attack earlier on average.")
        elif m1["latency_mean_steps"] < m2["latency_mean_steps"]:
            print("v1 flags the attack earlier on average.")
    print("\nSuggestion: run both side by side for defence-in-depth.")


if __name__ == "__main__":
    main()
