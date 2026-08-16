"""Evaluate the v1 heuristic detector on synthetic sessions.

Usage: python run_v1_test.py [--n-benign 60] [--n-ransom 60] [--seed 1337]
"""
from __future__ import annotations

import argparse
import tempfile

from tools.harness import evaluate_v1, make_sessions, print_report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-benign", type=int, default=60)
    ap.add_argument("--n-ransom", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-files", type=int, default=40)
    ap.add_argument("--n-windows", type=int, default=8)
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="rg_v1_")
    sessions = make_sessions(args.n_benign, args.n_ransom, args.seed, tmp,
                             n_files=args.n_files, n_windows=args.n_windows)
    results = []
    for i, s in enumerate(sessions):
        results.append(evaluate_v1(s))
        if (i + 1) % 30 == 0:
            print(f"  v1 evaluated {i + 1}/{len(sessions)} sessions")
    print_report(results, "v1 heuristic detector")


if __name__ == "__main__":
    main()
