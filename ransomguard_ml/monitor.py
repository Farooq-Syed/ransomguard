"""v2 runtime: continuous ML-based monitoring with anomaly layer + explanations.

Usage:
  python -m ransomguard_ml.monitor --model models/v2_model.pkl
"""
from __future__ import annotations

import argparse
import os
import pickle
import signal
import threading
from pathlib import Path

from ransomguard.alerter import Alerter
from ransomguard.config import load_config
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager
from ransomguard_ml.drift import DriftMonitor
from ransomguard_ml.explain import explain
from ransomguard_ml.features import extract_features
from ransomguard_ml.predict import predict_window

ROOT = Path(__file__).resolve().parent.parent


class MLMonitor:
    def __init__(self, config, model_path, alerter):
        with open(model_path, "rb") as fh:
            self.payload = pickle.load(fh)
        self.model = self.payload["model"]
        self.feature_names = self.payload["feature_names"]
        self.iforest = self.payload.get("iforest")
        self.alerter = alerter
        self.config = config
        manifest = ROOT / ".honeypot_manifest.json"
        self.honeypots = HoneypotManager(config, manifest)
        self.fs = FileSystemMonitor(config, alerter, self.honeypots)
        stats = self.payload.get("benign_stats", {"mean": 0.1, "std": 0.1})
        self.drift = DriftMonitor(stats["mean"], stats["std"], warn_z=config.drift_warn_z)
        self.history = {"rf_hist": [], "out_hist": [], "outlier_threshold": self.payload.get("outlier_threshold", -1e9)}

    def scan_once(self, events=None):
        batch = self.fs.classify_batch()
        if batch.get("status") == "baseline":
            self.alerter.emit(f"ML baseline snapshot: {batch['files']} files tracked.", "INFO")
            return batch, None
        feats = extract_features(batch, events or [], self.config, self.fs)
        vec = [feats[n] for n in self.feature_names]
        pred = predict_window(self.model, self.iforest, vec, self.history)
        level = pred["level"]

        reason = ""
        if level in ("HIGH", "CRITICAL", "PANDEMIC"):
            top = explain(self.model, vec, self.feature_names)
            reason = " why: " + ", ".join(f"{name}={coef:+.2f}" for name, coef in top) if top else ""
        if self.drift.update(pred["prob"]):
            self.alerter.emit("Baseline drift detected — recent ML scores far above benign training "
                              "distribution; consider retraining.", "WARN")

        self.alerter.emit(
            f"ML prob {pred['prob']:.2f} outlier={pred.get('outlier')} streak={pred.get('streak')} | "
            f"files {batch['files']}, mod {len(batch['modified'])}, new {len(batch['new'])}, "
            f"renamed {len(batch['renamed'])}, notes {len(batch['note'])}, "
            f"honeypot {len(batch['honeypot_hits'])}, silent_tamper {len(batch['silent_tamper'])}{reason}",
            level,
            dedup_key=f"ml:{level}",
        )
        return batch, pred


def run(model_path: str) -> None:
    config = load_config(ROOT / "config.json")
    alerter = Alerter(log_file=str(ROOT / config.log_file), webhook_url=config.webhook_url,
                      cef_log_file=config.cef_log_file or "")
    monitor = MLMonitor(config, model_path, alerter)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                monitor.scan_once()
            except Exception as exc:
                alerter.emit(f"ML scan error: {exc}", "WARN")
            stop.wait(config.scan_interval)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    alerter.emit("RansomGuard v2 (ML) active. Ctrl+C to stop.", "INFO")
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: stop.set())
        except (ValueError, OSError):
            pass
    try:
        while not stop.is_set():
            stop.wait(1.0)
    except KeyboardInterrupt:
        stop.set()
    t.join(timeout=2)
    print("\nRansomGuard v2 stopped.")


def main() -> None:
    ap = argparse.ArgumentParser(description="RansomGuard v2 ML monitor")
    ap.add_argument("--model", type=str, default=str(ROOT / "models" / "v2_model.pkl"))
    args = ap.parse_args()
    run(args.model)


if __name__ == "__main__":
    main()
