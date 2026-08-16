"""Train the v2 ML detector on synthetic benign/ransomware window data.

Usage:
  python train_v2.py --n-benign 400 --n-ransom 400 --seed 42 --out models/v2_model.pkl
"""
from __future__ import annotations

import argparse
import os
import pickle
import random
import tempfile
from pathlib import Path

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, roc_auc_score, precision_recall_fscore_support)

from ransomguard.config import Config
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager
from ransomguard_ml.features import FEATURE_NAMES, extract_features
from tools.harness import make_test_config, make_sessions

ROOT = Path(__file__).resolve().parent
MODEL_DIR = ROOT / "models"


def extract_session(session: dict, config) -> list[tuple[dict, int]]:
    sandbox = session["sandbox"]
    attack_start = session["attack_start"]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        manifest = os.path.join(tmp, "honey.json")
        hp = HoneypotManager(config, Path(manifest))
        hp.setup()
        fs = FileSystemMonitor(config, None, hp)
        fs.classify_batch()
        for w in range(session["n_windows"]):
            events = sandbox.step(w, attack_start, hp, session["rng"])
            batch = fs.classify_batch()
            feats = extract_features(batch, events, config, fs)
            label = 1 if (attack_start is not None and w >= attack_start) else 0
            rows.append((feats, label))
    return rows


def build_dataset(sessions: list[dict], config) -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for i, s in enumerate(sessions):
        for feats, label in extract_session(s, config):
            X.append([feats[n] for n in FEATURE_NAMES])
            y.append(label)
        if (i + 1) % 100 == 0:
            print(f"  processed {i + 1}/{len(sessions)} sessions")
    return np.asarray(X, dtype=float), np.asarray(y, dtype=int)


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
    config = make_test_config(sessions[0]["sandbox"].root, "", low_rate=False)
    print(f"Extracting window features ({len(sessions)} sessions)...")
    X, y = build_dataset(sessions, config)

    split = int(len(X) * 0.8)
    rng = np.random.RandomState(7)
    idx = rng.permutation(len(X))
    tr, te = idx[:split], idx[split:]
    Xtr, ytr, Xte, yte = X[tr], y[tr], X[te], y[te]

    print(f"Training RandomForest on {len(Xtr)} windows...")
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=14, min_samples_leaf=2,
        class_weight="balanced", random_state=0, n_jobs=-1,
    )
    rf.fit(Xtr, ytr)

    print("Calibrating probabilities (isotonic)...")
    model = CalibratedClassifierCV(rf, method="isotonic", cv=5)
    model.fit(Xtr, ytr)

    print("Training IsolationForest anomaly layer on benign windows...")
    Xb = X[y == 0]
    iforest = IsolationForest(n_estimators=200, contamination=0.01, random_state=0, n_jobs=-1)
    iforest.fit(Xb)
    benign_scores = iforest.decision_function(Xb)
    outlier_threshold = float(np.percentile(benign_scores, 1))

    benign_probas = model.predict_proba(Xb)[:, 1]
    benign_stats = {"mean": float(benign_probas.mean()), "std": float(benign_probas.std())}

    pred = model.predict(Xte)
    prob = model.predict_proba(Xte)[:, 1]
    prec, rec, f1, _ = precision_recall_fscore_support(yte, pred, average="binary")
    print("\n--- v2 model validation (20% holdout windows) ---")
    print(f"accuracy : {accuracy_score(yte, pred):.3f}")
    print(f"precision: {prec:.3f}   recall: {rec:.3f}   f1: {f1:.3f}")
    print(f"ROC AUC  : {roc_auc_score(yte, prob):.3f}")
    print(f"benign prob baseline: mean={benign_stats['mean']:.3f} std={benign_stats['std']:.3f}")
    print(f"IF outlier threshold: {outlier_threshold:.3f}")

    top = sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda t: -t[1])[:10]
    print("\ntop features:")
    for name, imp in top:
        print(f"  {name:<20} {imp:.3f}")

    payload = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "iforest": iforest,
        "outlier_threshold": outlier_threshold,
        "benign_stats": benign_stats,
        "trained_on": {"sessions": len(sessions), "windows": int(len(X))},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as fh:
        pickle.dump(payload, fh)
    print(f"\nModel saved to {out}")


if __name__ == "__main__":
    main()
