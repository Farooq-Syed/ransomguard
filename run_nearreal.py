"""Near-real-world evaluation: engines vs a distribution-shifted test set.

Training stays on the standard distribution (classic+stealth, seed 42). The
test set uses a different seed and includes attack styles never seen in
training (novel extensions/notes, and an entropy-evading wiper). This measures
generalisation to a shifted "real world" rather than the training distribution.

Usage: python run_nearreal.py [--seed 2024] [--n-benign 40] [--n-ransom 40]
"""
from __future__ import annotations

import argparse
import os
import tempfile

from ransomguard_ml.train import train_and_save
from tools.harness import evaluate_v1, evaluate_v2, make_mixed_sessions, make_test_config
from tools.results import bar_chart, save_json

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = os.path.join(ROOT, "results")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=2024)
    ap.add_argument("--n-benign", type=int, default=40)
    ap.add_argument("--n-ransom", type=int, default=40)
    ap.add_argument("--n-files", type=int, default=35)
    ap.add_argument("--n-windows", type=int, default=7)
    ap.add_argument("--noise", type=float, default=0.4)
    ap.add_argument("--train-benign", type=int, default=200)
    ap.add_argument("--train-ransom", type=int, default=200)
    ap.add_argument("--train-model", type=str, default=os.path.join(ROOT, "models", "v2_nearreal_train.pkl"))
    ap.add_argument("--tag", type=str, default="")
    args = ap.parse_args()
    os.makedirs(RESULT_DIR, exist_ok=True)
    tag = f"_{args.tag}" if args.tag else ""

    styles = ("classic", "stealth", "novel_ext", "wiper")
    tmp = tempfile.mkdtemp(prefix="rg_nr_")

    print("== Training v2 on standard distribution ==")
    train_tmp = tempfile.mkdtemp(prefix="rg_nr_train_")
    from tools.harness import make_sessions
    train_sessions = make_sessions(args.train_benign, args.train_ransom, 42, train_tmp,
                                   noise_benign=0.4, n_files=25, n_windows=6, stealth_frac=0.3)
    payload = train_and_save(train_sessions, args.train_model)

    print(f"== Building shifted test set (seed {args.seed}, styles {styles}) ==")
    sessions = make_mixed_sessions(args.n_benign, args.n_ransom, args.seed, tmp,
                                   styles=styles, noise=args.noise,
                                   n_files=args.n_files, n_windows=args.n_windows)

    results_v1, results_v2 = [], []
    for i, s in enumerate(sessions):
        cfg = make_test_config(s["sandbox"].root, "", low_rate=False)
        results_v1.append(evaluate_v1(s, cfg))
        results_v2.append(evaluate_v2(s, payload, cfg))
        if (i + 1) % 30 == 0:
            print(f"  evaluated {i + 1}/{len(sessions)} sessions")

    def per_style(results):
        out = {}
        for r in results:
            if r["kind"] != "ransomware":
                continue
            st = r.get("style") or "?"
            out.setdefault(st, {"n": 0, "det": 0})
            out[st]["n"] += 1
            if r["detected"]:
                out[st]["det"] += 1
        return {k: v["det"] / max(1, v["n"]) for k, v in out.items()}

    def fp_rate(results):
        benign = [r for r in results if r["kind"] == "benign"]
        return sum(1 for r in benign if r["false_alarm"]) / max(1, len(benign))

    d1, d2 = per_style(results_v1), per_style(results_v2)
    summary = {
        "seed": args.seed,
        "styles": list(styles),
        "n_sessions": len(sessions),
        "detection_by_style": {"v1": d1, "v2": d2},
        "false_positive_rate": {"v1": fp_rate(results_v1), "v2": fp_rate(results_v2)},
    }

    print("\n=== NEAR-REAL-WORLD (shifted distribution) ===")
    print(f"{'style':<12} {'v1':>8} {'v2':>8}")
    for st in styles:
        print(f"{st:<12} {d1.get(st, 0) * 100:>7.0f}% {d2.get(st, 0) * 100:>7.0f}%")
    print(f"{'benign FP rate':<12} {fp_rate(results_v1) * 100:>7.0f}% {fp_rate(results_v2) * 100:>7.0f}%")

    save_json(summary, os.path.join(RESULT_DIR, f"nearreal{tag}.json"))
    labels = list(styles) + ["benign FP"]
    s1 = [d1.get(st, 0) for st in styles] + [fp_rate(results_v1)]
    s2 = [d2.get(st, 0) for st in styles] + [fp_rate(results_v2)]
    bar_chart(labels, {"v1": s1, "v2": s2}, os.path.join(RESULT_DIR, f"nearreal{tag}.png"),
              "Near-real-world: detection rate by attack style (novel styles never seen in training)",
              "detection rate / FP rate")
    print(f"\nSaved results to {RESULT_DIR}/nearreal{tag}.json and nearreal{tag}.png")


if __name__ == "__main__":
    main()
