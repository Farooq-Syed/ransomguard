"""Lightweight model-agnostic local explanation (simplified LIME).

Perturbs the observed feature vector, records predicted probabilities, and fits
a small linear model to approximate the local decision boundary. The top
coefficients answer "why did the model flag this window?".
"""
from __future__ import annotations

import random

import numpy as np

N_PERTURB = 256
SEED = 7


def explain(model, feature_values: list[float], feature_names: list[str], top_n: int = 3) -> list[tuple[str, float]]:
    x0 = np.asarray(feature_values, dtype=float)
    rng = np.random.RandomState(SEED)
    noise = rng.normal(0.0, 0.15, size=(N_PERTURB, len(x0)))
    scale = np.abs(x0).clip(1.0)
    x_pert = np.maximum(0.0, x0 + noise * scale)

    try:
        base_prob = float(model.predict_proba([x0])[0, 1])
        pert_probs = model.predict_proba(x_pert)[:, 1]
    except Exception:
        return []

    deltas = pert_probs - base_prob
    A = x_pert - x0
    try:
        coef, *_ = np.linalg.lstsq(A, deltas, rcond=None)
    except np.linalg.LinAlgError:
        return []

    ranked = sorted(zip(feature_names, coef.tolist()), key=lambda t: -abs(t[1]))
    return ranked[:top_n]
