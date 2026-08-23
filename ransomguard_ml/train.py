"""Core v2 training pipeline: features -> calibrated RF + IsolationForest -> payload.

Used by train_v2.py (single-shot) and run_walkforward.py (per-fold retraining).
"""
from __future__ import annotations

import os
import pickle
import tempfile
from pathlib import Path

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score

from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager
from ransomguard_ml.features import FEATURE_NAMES, extract_features
from tools.harness import make_test_config


def extract_session(session: dict, config=None) -> list[tuple[dict, int]]:
    """Extract one session's window features against THAT session's own sandbox.

    A per-session ``config`` is required so the FileSystemMonitor and
    HoneypotManager watch this session's directory rather than being shared
    across the whole corpus. Passing a config built from a *different*
    session's root silently contaminates the filesystem features.
    """
    sandbox = session["sandbox"]
    attack_start = session["attack_start"]
    if config is None:
        config = make_test_config(sandbox.root, "", low_rate=False)
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


def build_dataset(sessions: list[dict], config=None) -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for i, s in enumerate(sessions):
        for feats, label in extract_session(s, config):
            X.append([feats[n] for n in FEATURE_NAMES])
            y.append(label)
        if (i + 1) % 100 == 0:
            print(f"  processed {i + 1}/{len(sessions)} sessions")
    return np.asarray(X, dtype=float), np.asarray(y, dtype=int)


def fit_models(X: np.ndarray, y: np.ndarray, verbose: bool = True):
    split = int(len(X) * 0.8)
    rng = np.random.RandomState(7)
    idx = rng.permutation(len(X))
    tr, te = idx[:split], idx[split:]
    Xtr, ytr, Xte, yte = X[tr], y[tr], X[te], y[te]

    rf = RandomForestClassifier(
        n_estimators=300, max_depth=14, min_samples_leaf=2,
        class_weight="balanced", random_state=0, n_jobs=-1,
    )
    rf.fit(Xtr, ytr)
    model = CalibratedClassifierCV(rf, method="isotonic", cv=5)
    model.fit(Xtr, ytr)

    Xb = X[y == 0]
    iforest = IsolationForest(n_estimators=200, contamination=0.01, random_state=0, n_jobs=-1)
    iforest.fit(Xb)
    benign_scores = iforest.decision_function(Xb)
    outlier_threshold = float(np.percentile(benign_scores, 1))

    benign_probas = model.predict_proba(Xb)[:, 1]
    benign_stats = {"mean": float(benign_probas.mean()), "std": float(benign_probas.std())}

    if verbose:
        pred = model.predict(Xte)
        prob = model.predict_proba(Xte)[:, 1]
        print("  holdout:", {"acc": round(accuracy_score(yte, pred), 3),
                             "auc": round(roc_auc_score(yte, prob), 3)})
    return model, iforest, outlier_threshold, benign_stats


def train_and_save(sessions: list[dict], out_path: str | Path, verbose: bool = True):
    X, y = build_dataset(sessions)
    model, iforest, outlier_threshold, benign_stats = fit_models(X, y, verbose=verbose)
    payload = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "iforest": iforest,
        "outlier_threshold": outlier_threshold,
        "benign_stats": benign_stats,
        "trained_on": {"sessions": len(sessions), "windows": int(len(X))},
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "wb") as fh:
        pickle.dump(payload, fh)
    return payload
