"""Train the v2 ML detector on synthetic benign/ransomware window data.

Usage:
  python train_v2.py --n-benign 400 --n-ransom 400 --seed 42 --out models/v2_model.pkl
"""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from ransomguard_ml.features import FEATURE_NAMES
from ransomguard_ml.train import train_and_save
from tools.harness import make_sessions

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-benign", type=int, default=400)
    ap.add_argument("--n-ransom", type=int, default=400)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-files", type=int, default=30)
    ap.add_argument("--n-windows", type=int, default=6)
    ap.add_argument("--noise-benign", type=float, default=0.4)
    ap.add_argument("--stealth-frac", type=float, default=0.3)
    ap.add_argument("--out", type=str, default=str(MODEL_DIR / "v2_model.pkl"))
    args = ap.parse_args()

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    tmp_root = tempfile.mkdtemp(prefix="rg_train_")
    print("Generating training sessions...")
    sessions = make_sessions(args.n_benign, args.n_ransom, args.seed, tmp_root,
                             noise_benign=args.noise_benign, n_files=args.n_files,
                             n_windows=args.n_windows, stealth_frac=args.stealth_frac)
    print(f"Extracting window features ({len(sessions)} sessions)...")
    payload = train_and_save(sessions, args.out)
    model = payload["model"]

    top = sorted(zip(FEATURE_NAMES, model.estimator.feature_importances_ if hasattr(model, "estimator") else model.feature_importances_),
                 key=lambda t: -t[1])[:10]
    print("\ntop features:")
    for name, imp in top:
        print(f"  {name:<20} {imp:.3f}")

    print(f"\nModel saved to {args.out}")


if __name__ == "__main__":
    main()
