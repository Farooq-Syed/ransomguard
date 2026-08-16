"""v2 runtime: continuous ML-based monitoring.

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
from ransomguard_ml.features import extract_features

ROOT = Path(__file__).resolve().parent.parent


class MLMonitor:
    def __init__(self, config, model_path, alerter):
        with open(model_path, "rb") as fh:
            payload = pickle.load(fh)
        self.model = payload["model"]
        self.feature_names = payload["feature_names"]
        self.alerter = alerter
        self.config = config
        manifest = ROOT / ".honeypot_manifest.json"
        self.honeypots = HoneypotManager(config, manifest)
        self.fs = FileSystemMonitor(config, alerter, self.honeypots)
        self._streak = 0

    def scan_once(self, events=None):
        batch = self.fs.classify_batch()
        if batch.get("status") == "baseline":
            self.alerter.emit(f"ML baseline snapshot: {batch['files']} files tracked.", "INFO")
            return batch, None
        feats = extract_features(batch, events or [], self.config, self.fs)
        vec = [[feats[n] for n in self.feature_names]]
        prob = float(self.model.predict_proba(vec)[0, 1])
        if prob >= 0.9:
            level = "CRITICAL"
            self._streak += 1
        elif prob >= 0.7:
            level = "HIGH"
            self._streak += 1
        elif prob >= 0.5:
            level = "WARN"
            self._streak = 0
        else:
            level = "INFO"
            self._streak = 0
        if level == "CRITICAL" and self._streak >= 2:
            level = "PANDEMIC"
        self.alerter.emit(
            f"ML prob {prob:.2f} | files {batch['files']}, mod {len(batch['modified'])}, "
            f"new {len(batch['new'])}, renamed {len(batch['renamed'])}, notes {len(batch['note'])}, "
            f"honeypot {len(batch['honeypot_hits'])}",
            level,
            dedup_key=f"ml:{level}",
        )
        return batch, {"prob": prob, "level": level}


def run(model_path: str) -> None:
    config = load_config(ROOT / "config.json")
    alerter = Alerter(log_file=str(ROOT / config.log_file), webhook_url=config.webhook_url)
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
