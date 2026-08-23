"""Standalone ransomware example runner for manual RansomGuard checks.

Creates one synthetic ransomware session in a throwaway sandbox, feeds it through
the v1 detector window by window, and prints the alerts that fired. This is the
quickest way to demonstrate that RansomGuard still reacts to ransomware-style
behavior without running the larger benchmark suites.

Usage:
    python simulate_ransomware_example.py
    python simulate_ransomware_example.py --style wiper --seed 2026 --keep-sandbox
"""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from tools.harness import RecordingAlerter, make_test_config
from tools.simulate import build_session

from ransomguard.detector import Detector
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one standalone synthetic ransomware example against RansomGuard."
    )
    parser.add_argument("--seed", type=int, default=2026, help="Random seed for reproducible output.")
    parser.add_argument(
        "--style",
        choices=["classic", "stealth", "novel_ext", "wiper"],
        default="classic",
        help="Attack style to simulate.",
    )
    parser.add_argument("--n-files", type=int, default=35, help="Number of initial files in the sandbox.")
    parser.add_argument("--n-windows", type=int, default=7, help="Number of activity windows to simulate.")
    parser.add_argument(
        "--keep-sandbox",
        action="store_true",
        help="Keep the generated sandbox directory after the run for inspection.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    temp_ctx = tempfile.TemporaryDirectory(prefix="rg_example_")
    sandbox_root = Path(temp_ctx.name)
    try:
        session = build_session(
            "ransomware",
            str(sandbox_root),
            __import__("random").Random(args.seed),
            n_files=args.n_files,
            n_windows=args.n_windows,
            noise=0.0,
            attack_style=args.style,
        )

        manifest = sandbox_root / "honeypots.json"
        config = make_test_config(str(sandbox_root), str(manifest), low_rate=True)
        alerter = RecordingAlerter()
        honeypots = HoneypotManager(config, manifest)
        honeypots.setup()
        detector = Detector(config, alerter)
        fs = FileSystemMonitor(config, alerter, honeypots)

        baseline = fs.classify_batch()
        detector.handle_scan(baseline)

        print(f"Sandbox       : {sandbox_root}")
        print(f"Attack style  : {args.style}")
        print(f"Attack starts : window {session['attack_start']}")
        print(f"Windows       : {args.n_windows}")
        print()

        for window_index in range(args.n_windows):
            before = len(alerter.history)
            events = session["sandbox"].step(window_index, session["attack_start"], honeypots, session["rng"])
            detector.handle_scan(fs.classify_batch())
            detector.handle_events(events)
            new_alerts = alerter.history[before:]

            attack_live = window_index >= session["attack_start"]
            print(f"Window {window_index}: attack_live={attack_live} alerts={len(new_alerts)}")
            for level, message in new_alerts[:5]:
                print(f"  [{level}] {message}")
            if len(new_alerts) > 5:
                print(f"  ... {len(new_alerts) - 5} more alert(s)")

        fired_levels = [level for level, _ in alerter.history]
        detected = any(level in {"HIGH", "CRITICAL", "PANDEMIC"} for level in fired_levels)
        print()
        print(f"Detected      : {detected}")
        print(f"Alerts fired  : {len(alerter.history)}")
        if args.keep_sandbox:
            print(f"Sandbox kept  : {sandbox_root}")
            temp_ctx.cleanup = lambda: None  # type: ignore[attr-defined]
        return 0 if detected else 1
    finally:
        if not args.keep_sandbox:
            temp_ctx.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
