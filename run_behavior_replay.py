"""Multi-scenario contained ransomware-behavior replay for RansomGuard.

Runs MANY distinct ransomware-style *behavioral* scenarios through the detector and
reports detection per scenario. This is "many ransomware samples" for real-data-style
testing — but legally and safely: each scenario is only file I/O inside an isolated
temporary sandbox (writes/renames/drops note files). There is NO malware payload, NO
persistence, NO network activity, and nothing runs outside the sandbox directory.

Containment guarantees (why this cannot spread):
  - every write/rename/unlink is under a `tempfile.TemporaryDirectory()` sandbox root;
  - no registry / scheduled-task / autostart / boot modification;
  - no sockets, no C2, no spreading; the only "network/process" signals are event dicts
    fed to the detector, never real system actions;
  - the sandbox is deleted after the run unless --keep-sandbox is passed.

Usage:
    python run_behavior_replay.py                      # built-in scenario grid
    python run_behavior_replay.py --rounds 12          # random scenarios, reproducible
"""

from __future__ import annotations

import argparse
import json
import random
import tempfile
from pathlib import Path

from tools.harness import RecordingAlerter, make_test_config
from tools.simulate import build_session

from ransomguard.detector import Detector
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager

STYLES = ["classic", "stealth", "novel_ext", "wiper"]
ALERT_LEVELS = ("HIGH", "CRITICAL", "PANDEMIC")


def run_scenario(style: str, seed: int, n_files: int = 35, n_windows: int = 7,
                 noise: float = 0.0) -> dict:
    """Run one contained scenario; return detection metrics."""
    with tempfile.TemporaryDirectory(prefix="rg_replay_") as tmp:
        sandbox_root = Path(tmp)
        session = build_session("ransomware", str(sandbox_root), random.Random(seed),
                                n_files=n_files, n_windows=n_windows, noise=noise,
                                attack_style=style)
        manifest = sandbox_root / "honeypots.json"
        config = make_test_config(str(sandbox_root), str(manifest), low_rate=True)
        alerter = RecordingAlerter()
        honeypots = HoneypotManager(config, manifest)
        honeypots.setup()
        detector = Detector(config, alerter)
        fs = FileSystemMonitor(config, alerter, honeypots)
        detector.handle_scan(fs.classify_batch())

        attack_start = session["attack_start"]
        first_alert_at = None
        for window_index in range(n_windows):
            events = session["sandbox"].step(window_index, attack_start, honeypots, session["rng"])
            detector.handle_scan(fs.classify_batch())
            detector.handle_events(events)
            if first_alert_at is None and any(level in ALERT_LEVELS for level, _ in alerter.history):
                first_alert_at = window_index

        fired = [level for level, _ in alerter.history]
        detected = any(level in ALERT_LEVELS for level in fired)
        latency = (first_alert_at - attack_start) if (detected and first_alert_at is not None) else None
        return {
            "style": style, "seed": seed, "attack_start": attack_start,
            "leading_windows": attack_start,
            "detected": detected,
            "latency_windows": latency,
            "alerts": len(fired),
            "caught_in_attack_windows": detected and (first_alert_at is not None and first_alert_at >= attack_start),
        }


def build_grid(rounds: int) -> list[dict]:
    """Deterministic grid covering every style across a spread of seeds."""
    grid = []
    for i in range(rounds):
        style = STYLES[i % len(STYLES)]
        seed = 1000 + (i // len(STYLES)) * 7 + i % len(STYLES)
        grid.append({"style": style, "seed": seed})
    return grid


def main() -> int:
    ap = argparse.ArgumentParser(description="Contained multi-scenario ransomware replay.")
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--keep-sandbox-info", action="store_true", help="Print per-scenario details.")
    ap.add_argument("--out", default="results/behavior_replay.json")
    args = ap.parse_args()

    scenarios = build_grid(args.rounds)
    results = []
    for spec in scenarios:
        res = run_scenario(spec["style"], spec["seed"])
        results.append(res)
        print(f"  {res['style']:<10} seed={res['seed']:<6} detected={res['detected']}"
              f"  latency={res['latency_windows']}  alerts={res['alerts']}")

    n = len(results)
    detected = sum(1 for r in results if r["detected"])
    early = sum(1 for r in results if r["caught_in_attack_windows"])
    latencies = [r["latency_windows"] for r in results if r["latency_windows"] is not None]
    summary = {
        "scenarios": n,
        "detected": detected,
        "detection_rate": round(detected / max(1, n), 3),
        "detected_within_attack_windows": early,
        "mean_latency_windows": round(sum(latencies) / len(latencies), 2) if latencies else None,
        "by_style": {s: {"n": sum(1 for r in results if r["style"] == s),
                         "detected": sum(1 for r in results if r["style"] == s and r["detected"])}
                     for s in STYLES},
        "results": results,
    }
    json.dump(summary, Path(args.out).open("w"), ensure_ascii=False, indent=2)
    print("\n=== Contained ransomware-behavior replay ===")
    print(f"scenarios  : {n}")
    print(f"detected   : {detected}/{n} ({summary['detection_rate'] * 100:.0f}%)")
    print(f"within attack windows: {early}/{n}")
    print(f"mean latency (windows): {summary['mean_latency_windows']}")
    print(f"written to: {args.out}")
    print("\nSafety: all scenarios are file I/O inside isolated temp sandboxes; no persisence, no network, no payload.")
    return 0 if detected == n else 1


if __name__ == "__main__":
    raise SystemExit(main())
