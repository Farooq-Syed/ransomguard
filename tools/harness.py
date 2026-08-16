"""Evaluation harness: runs v1 (heuristic) and v2 (ML) on identical simulations."""
from __future__ import annotations

import os
import random
import shutil
import tempfile
from pathlib import Path

from ransomguard.alerter import Alerter
from ransomguard.config import Config, DEFAULT_CONFIG, deep_merge
from ransomguard.detector import Detector
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager

from tools.simulate import build_session

ALERT_LEVELS = ("HIGH", "CRITICAL", "PANDEMIC")


class RecordingAlerter(Alerter):
    def __init__(self):
        super().__init__(log_file="", webhook_url="")
        self._cooldown = 0.0
        self.history: list[tuple[str, str]] = []

    def emit(self, message, level="INFO", dedup_key=None):
        self.history.append((level, message))


def make_test_config(sandbox_root: str, manifest_path: str, low_rate: bool = False,
                     rate_warn: int | None = None, rate_critical: int | None = None) -> Config:
    overrides = {
        "watch_dirs": [{"path": sandbox_root, "priority": 70, "recursive": True}],
        "watch_files": [],
        "honeypot_dirs": [{"path": sandbox_root, "count": 2}],
        "honeypot_prefix": "~canary_",
        "quarantine_dir": "",
        "log_file": "",
        "webhook_url": "",
        "aged_days": 30,
        "mod_rate_window_seconds": 60,
        "mod_rate_warn": 100,
        "mod_rate_critical": 600,
    }
    if low_rate:
        overrides["mod_rate_warn"] = 25
        overrides["mod_rate_critical"] = 60
    if rate_warn is not None:
        overrides["mod_rate_warn"] = rate_warn
    if rate_critical is not None:
        overrides["mod_rate_critical"] = rate_critical
    return Config(deep_merge(DEFAULT_CONFIG, overrides))


def make_sessions(n_benign: int, n_ransom: int, seed: int, base_root: str,
                  noise_benign: float = 0.2, noise_ransom: float = 0.0,
                  n_files: int = 35, n_windows: int = 8,
                  stealth_frac: float = 0.0) -> list[dict]:
    rng = random.Random(seed)
    sessions = []
    idx = 0
    for _ in range(n_benign):
        root = os.path.join(base_root, f"b_{idx}")
        sessions.append(build_session("benign", root, random.Random(rng.randrange(1 << 30)),
                                      n_files=n_files, n_windows=n_windows, noise=noise_benign))
        idx += 1
    for i in range(n_ransom):
        root = os.path.join(base_root, f"r_{idx}")
        style = "stealth" if (i / max(1, n_ransom)) < stealth_frac else "classic"
        sessions.append(build_session("ransomware", root, random.Random(rng.randrange(1 << 30)),
                                      n_files=n_files, n_windows=n_windows, noise=noise_ransom,
                                      attack_style=style))
        idx += 1
    random.Random(seed + 1).shuffle(sessions)
    return sessions


def make_mixed_sessions(n_benign: int, n_ransom: int, seed: int, base_root: str,
                        styles: tuple = ("classic", "stealth", "novel_ext", "wiper"),
                        noise: float = 0.4, n_files: int = 35, n_windows: int = 8) -> list[dict]:
    """Near-real eval set: a mixture of attack styles (some never seen in training)
    under a different seed and noise profile than training."""
    rng = random.Random(seed)
    sessions = []
    idx = 0
    for _ in range(n_benign):
        root = os.path.join(base_root, f"b_{idx}")
        sessions.append(build_session("benign", root, random.Random(rng.randrange(1 << 30)),
                                      n_files=n_files, n_windows=n_windows, noise=noise))
        idx += 1
    for _ in range(n_ransom):
        root = os.path.join(base_root, f"r_{idx}")
        style = random.Random(rng.randrange(1 << 30)).choice(styles)
        sessions.append(build_session("ransomware", root, random.Random(rng.randrange(1 << 30)),
                                      n_files=n_files, n_windows=n_windows, noise=noise,
                                      attack_style=style))
        idx += 1
    random.Random(seed + 1).shuffle(sessions)
    return sessions


def run_windows(session: dict, feed) -> list[dict]:
    """feed(batch, events) -> list of emitted levels for this window."""
    sandbox = session["sandbox"]
    rng = session["rng"]
    attack_start = session["attack_start"]
    out = []
    for w in range(session["n_windows"]):
        events = sandbox.step(w, attack_start, None, rng)
        levels = feed(events)
        out.append({"window": w, "attack": attack_start is not None and w >= attack_start, "levels": levels})
    return out


def evaluate_v1(session: dict, config=None) -> dict:
    sandbox = session["sandbox"]
    with tempfile.TemporaryDirectory() as tmp:
        manifest = os.path.join(tmp, "honey.json")
        config = config or make_test_config(sandbox.root, manifest)
        alerter = RecordingAlerter()
        hp = HoneypotManager(config, Path(manifest))
        hp.setup()
        detector = Detector(config, alerter)
        fs = FileSystemMonitor(config, alerter, hp)
        detector.handle_scan(fs.classify_batch())

        results = []
        attack_start = session["attack_start"]
        for w in range(session["n_windows"]):
            events = sandbox.step(w, attack_start, hp, session["rng"])
            before = len(alerter.history)
            detector.handle_scan(fs.classify_batch())
            detector.handle_events(events)
            window_levels = [lv for lv, _ in alerter.history[before:]]
            results.append({"window": w, "levels": window_levels})
        return summarize(session, results)


def evaluate_v2(session: dict, payload: dict, config=None) -> dict:
    from ransomguard_ml.features import extract_features
    from ransomguard_ml.predict import predict_window

    model = payload["model"]
    feature_names = payload["feature_names"]
    iforest = payload.get("iforest")

    sandbox = session["sandbox"]
    with tempfile.TemporaryDirectory() as tmp:
        manifest = os.path.join(tmp, "honey.json")
        config = config or make_test_config(sandbox.root, manifest)
        alerter = RecordingAlerter()
        hp = HoneypotManager(config, Path(manifest))
        hp.setup()
        fs = FileSystemMonitor(config, alerter, hp)
        detector = Detector(config, alerter)
        detector.handle_scan(fs.classify_batch())

        history = {"rf_hist": [], "out_hist": [], "outlier_threshold": payload.get("outlier_threshold", -1e9)}
        results = []
        attack_start = session["attack_start"]
        for w in range(session["n_windows"]):
            events = sandbox.step(w, attack_start, hp, session["rng"])
            batch = fs.classify_batch()
            features = extract_features(batch, events, config, fs)
            vec = [features[n] for n in feature_names]
            pred = predict_window(model, iforest, vec, history)
            results.append({"window": w, "prob": pred["prob"], "level": pred["level"]})
        return summarize(session, results, use_prob=True)


def summarize_results(results: list[dict]) -> dict:
    benign = [r for r in results if r["kind"] == "benign"]
    ransom = [r for r in results if r["kind"] == "ransomware"]
    tp = sum(1 for r in ransom if r["detected"])
    fp = sum(1 for r in benign if r["false_alarm"])
    tn = len(benign) - fp
    fn = len(ransom) - tp
    latencies = [r["latency"] for r in ransom if r.get("detected") and r.get("latency") is not None]
    lat_mean = round(sum(latencies) / len(latencies), 2) if latencies else None
    by_style = {}
    for style in ("classic", "stealth"):
        group = [r for r in ransom if r.get("style") == style]
        if group:
            by_style[style] = {
                "n": len(group),
                "detected": sum(1 for r in group if r["detected"]),
            }
    return {
        "benign": len(benign),
        "ransomware": len(ransom),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "detection_rate": tp / max(1, len(ransom)),
        "false_positive_rate": fp / max(1, len(benign)),
        "latency_mean_steps": lat_mean,
        "by_style": by_style,
    }


def print_report(results: list[dict], label: str) -> None:
    m = summarize_results(results)
    print(f"\n=== {label} ===")
    print(f"  benign sessions    : {m['benign']}  (TP=., FP={m['fp']}, TN={m['tn']})")
    print(f"  ransomware sessions: {m['ransomware']}  (TP={m['tp']}, FN={m['fn']})")
    print(f"  detection rate     : {m['detection_rate'] * 100:.1f}%")
    print(f"  false positive rate: {m['false_positive_rate'] * 100:.1f}%")
    print(f"  mean latency (steps): {m['latency_mean_steps']}")


def summarize(session: dict, results: list[dict], use_prob: bool = False) -> dict:
    attack_start = session["attack_start"]
    benign = attack_start is None
    det = None
    detected_at = None
    false_alarm = False
    max_alarm = None
    for r in results:
        if use_prob:
            levels = [r["level"]]
            prob = r.get("prob", 0)
        else:
            levels = r["levels"]
        has_alarm = any(lv in ALERT_LEVELS for lv in levels)
        if has_alarm:
            max_alarm = max([lv for lv in levels if lv in ALERT_LEVELS])
            if benign:
                false_alarm = True
            else:
                if attack_start is not None and r["window"] >= attack_start and det is None:
                    det = True
                    detected_at = r["window"] - attack_start
    if not benign:
        det = bool(det) or detected_at is not None
    return {
        "kind": session["kind"],
        "style": session.get("attack_style"),
        "detected": det,
        "false_alarm": false_alarm,
        "latency": detected_at,
        "max_alarm": max_alarm,
        "results": results,
    }
