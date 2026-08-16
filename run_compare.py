"""Head-to-head comparison: v1 (heuristics) vs v2 (ML) on identical sessions.

Usage: python run_compare.py [--model models/v2_model.pkl] [--seed 1337]
"""
from __future__ import annotations

import argparse
import pickle
import tempfile

from tools.harness import evaluate_v1, evaluate_v2, make_sessions, make_test_config, summarize_results


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=str, default="models/v2_model.pkl")
    ap.add_argument("--n-benign", type=int, default=60)
    ap.add_argument("--n-ransom", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-files", type=int, default=40)
    ap.add_argument("--n-windows", type=int, default=8)
    ap.add_argument("--noise-benign", type=float, default=0.4)
    ap.add_argument("--stealth-frac", type=float, default=0.3)
    ap.add_argument("--prod-rates", action="store_true",
                    help="use production-like rate thresholds (warn 100/min, critical 600/min)")
    args = ap.parse_args()

    with open(args.model, "rb") as fh:
        payload = pickle.load(fh)

    tmp = tempfile.mkdtemp(prefix="rg_cmp_")
    sessions = make_sessions(args.n_benign, args.n_ransom, args.seed, tmp,
                             n_files=args.n_files, n_windows=args.n_windows,
                             noise_benign=args.noise_benign, stealth_frac=args.stealth_frac)
    rates = "(production rate thresholds)" if args.prod_rates else "(test/aggressive rate thresholds)"
    print(f"Comparing on {len(sessions)} sessions (seed {args.seed}, "
          f"benign noise {args.noise_benign}, stealth {int(args.stealth_frac * 100)}%) {rates}\n")

    r1, r2 = [], []
    for i, s in enumerate(sessions):
        cfg = make_test_config(s["sandbox"].root, "", low_rate=not args.prod_rates)
        r1.append(evaluate_v1(s, cfg))
        r2.append(evaluate_v2(s, payload, cfg))
        if (i + 1) % 30 == 0:
            print(f"  evaluated {i + 1}/{len(sessions)} sessions")

    m1, m2 = summarize_results(r1), summarize_results(r2)

    def pct(v):
        return f"{v * 100:.1f}%"

    print("metric                      v1         v2")
    print(f"{'Detection rate (TPR)':<26} v1 {pct(m1['detection_rate']):>8}    v2 {pct(m2['detection_rate']):>8}")
    print(f"{'False-positive rate':<26} v1 {pct(m1['false_positive_rate']):>8}    v2 {pct(m2['false_positive_rate']):>8}   (lower = better)")
    print(f"{'TP / FN':<26} v1 {m1['tp']:>3} / {m1['fn']:<3}    v2 {m2['tp']:>3} / {m2['fn']:<3}")
    print(f"{'FP / TN':<26} v1 {m1['fp']:>3} / {m1['tn']:<3}    v2 {m2['fp']:>3} / {m2['tn']:<3}")
    print(f"{'Mean latency (steps)':<26} v1 {str(m1['latency_mean_steps']):>8}    v2 {str(m2['latency_mean_steps']):>8}")

    print("\nDetection by attack style:")
    for style in ("classic", "stealth"):
        g1 = m1["by_style"].get(style, {})
        g2 = m2["by_style"].get(style, {})
        print(f"  {style:<8} v1 {g1.get('detected', 0)}/{g1.get('n', 0)}    v2 {g2.get('detected', 0)}/{g2.get('n', 0)}")

    print("\n--- verdict ---")
    dr1, dr2 = m1["detection_rate"], m2["detection_rate"]
    fr1, fr2 = m1["false_positive_rate"], m2["false_positive_rate"]
    if dr1 == dr2:
        det = f"Both engines caught the same share of attacks ({dr1 * 100:.0f}%)."
    elif dr2 > dr1:
        det = f"v2 caught a higher share of attacks ({dr2 * 100:.0f}% vs v1 {dr1 * 100:.0f}%)."
    else:
        det = f"v1 caught a higher share of attacks ({dr1 * 100:.0f}% vs v2 {dr2 * 100:.0f}%)."
    if fr2 < fr1:
        prec = f"v2 was more precise: false-positive rate {fr2 * 100:.1f}% vs v1 {fr1 * 100:.1f}%."
    elif fr1 < fr2:
        prec = f"v1 was more precise: false-positive rate {fr1 * 100:.1f}% vs v2 {fr2 * 100:.1f}%."
    else:
        prec = f"Both had the same false-positive rate ({fr1 * 100:.1f}%)."
    print(det + " " + prec)
    if m2["latency_mean_steps"] is not None and m1["latency_mean_steps"] is not None:
        if m2["latency_mean_steps"] < m1["latency_mean_steps"]:
            print("v2 flags the attack earlier on average.")
        elif m1["latency_mean_steps"] < m2["latency_mean_steps"]:
            print("v1 flags the attack earlier on average.")
    print("\nSuggestion: run both side by side for defence-in-depth.")


if __name__ == "__main__":
    main()
