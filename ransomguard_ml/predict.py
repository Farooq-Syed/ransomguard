"""Unified v2 prediction: supervised RF + unsupervised IsolationForest + streak.

Both the runtime monitor and the evaluation harness use this single function so
training and test behave identically.

The RF is the primary classifier. The IsolationForest is a *corroborating* layer
for novel attacks: an outlier alone never fires an alert; it can only bump the
level one notch when it repeats across windows AND the RF is at least borderline.
"""
from __future__ import annotations

ALERT_LEVELS = ("HIGH", "CRITICAL", "PANDEMIC")

_BORDERLINE = 0.45
_STREAK = 5


def predict_window(model, iforest, feature_values: list[float], history: dict) -> dict:
    rf_prob = float(model.predict_proba([feature_values])[0, 1])
    if_score = None
    outlier = False
    if iforest is not None:
        if_score = float(iforest.decision_function([feature_values])[0])
        outlier = if_score <= history["outlier_threshold"]

    history["rf_hist"].append(rf_prob)
    history["out_hist"].append(outlier)
    if len(history["rf_hist"]) > _STREAK:
        history["rf_hist"].pop(0)
        history["out_hist"].pop(0)

    streak = sum(1 for x in history["rf_hist"] if x >= _BORDERLINE) + sum(1 for x in history["out_hist"] if x)
    streak_flag = streak >= 2 and (rf_prob >= _BORDERLINE or outlier)

    if rf_prob >= 0.9:
        level = "CRITICAL"
    elif rf_prob >= 0.7:
        level = "HIGH"
    elif rf_prob >= 0.5:
        level = "WARN"
    else:
        level = "INFO"

    if outlier and streak_flag:
        if level == "INFO":
            level = "WARN"
        elif level == "WARN":
            level = "HIGH"
        elif level == "HIGH":
            level = "CRITICAL"

    if level == "CRITICAL" and streak >= 2:
        level = "PANDEMIC"

    return {"prob": rf_prob, "outlier": outlier, "if_score": if_score, "level": level, "streak": streak}
