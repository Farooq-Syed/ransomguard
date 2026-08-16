"""RansomGuard - ransomware early-warning monitor.

Usage:
  python main.py                      start continuous monitoring
  python main.py --setup-honeypots    plant decoy canary files
  python main.py --scan-once          one-shot prioritized inventory report
  python main.py --check-config       validate configuration and exit
  python main.py --freeze-now         emergency: kill suspicious processes
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ransomguard.alerter import Alerter
from ransomguard.config import load_config, write_default_config
from ransomguard.detector import Detector
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager
from ransomguard.process_monitor import ProcessMonitor
from ransomguard.resource_monitor import ResourceMonitor
from ransomguard import utils

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
MANIFEST_PATH = ROOT / ".honeypot_manifest.json"


def cmd_setup_honeypots(config) -> None:
    hp = HoneypotManager(config, MANIFEST_PATH)
    created = hp.setup()
    print(f"Planted {len(created)} honeypot canary files.")
    for p in created:
        print(f"  {p}")


def cmd_remove_honeypots(config) -> None:
    hp = HoneypotManager(config, MANIFEST_PATH)
    hp.remove()
    print("Removed all honeypot canary files.")


def cmd_scan_once(config) -> None:
    alerter = Alerter(log_file="")
    hp = HoneypotManager(config, MANIFEST_PATH)
    fs = FileSystemMonitor(config, alerter, hp)
    batch = fs.classify_batch()
    print(f"Scanned {batch['files']} files across watched locations.\n")
    rows = []
    for path, entry in fs._baseline.items():
        priority = fs.priority_for(path)
        base = os.path.basename(path)
        ext = utils.get_ext(base)
        flags = []
        if utils.is_target_ext(ext):
            flags.append("TARGETED")
        if utils.is_high_value_ext(ext):
            flags.append("HIGH-VALUE")
        if utils.is_known_ransomware_ext(base):
            flags.append("RANSOM-EXT?")
        rows.append((priority, path, " ".join(flags)))
    rows.sort(key=lambda r: -r[0])
    print(f"{'PRIO':>4}  {'PATH':<70}  FLAGS")
    for prio, path, flags in rows[:60]:
        print(f"{prio:>4}  {path:<70}  {flags}")
    print(f"\nTracked {len(rows)} files; {sum(1 for r in rows if 'TARGETED' in r[2])} in the top ransomware-target list.")


def cmd_check_config(config) -> None:
    print(f"scan_interval:      {config.scan_interval}s")
    print(f"entropy_threshold:  {config.entropy_threshold}")
    print(f"rate warn/critical: {config.rate_warn}/{config.rate_critical} per {config.rate_window}s")
    print(f"auto_freeze:        {config.auto_freeze}")
    print(f"quarantine_dir:     {config.quarantine_dir}")
    print(f"webhook:            {'configured' if config.webhook_url else 'disabled'}")
    print(f"watch_dirs:         {len(config.watch_dirs)}")
    print(f"watch_files:        {len(config.watch_files)}")
    missing = [d["path"] for d in config.watch_dirs if not os.path.isdir(os.path.expandvars(os.path.expanduser(d["path"])))]
    if missing:
        print("NOTE: missing watch dirs (ignored at runtime):")
        for m in missing:
            print(f"  {m}")
    print("\nConfiguration OK.")


def cmd_freeze_now(config) -> None:
    try:
        import psutil
    except ImportError:
        print("psutil required for freeze. pip install psutil")
        return
    stopped = 0
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
            name = (proc.info.get("name") or "").lower()
            if name in config.suspicious_names or any(p in cmd for p in config.shadowcopy_patterns):
                proc.suspend()
                print(f"Suspended {proc.info.get('name')} pid={proc.info.get('pid')}")
                stopped += 1
        except (psutil.Error, OSError):
            continue
    if not stopped:
        print("No obviously suspicious processes found (only suspends known tools).")


def run(config) -> None:
    alerter = Alerter(log_file=str(ROOT / config.log_file), webhook_url=config.webhook_url)
    honeypots = HoneypotManager(config, MANIFEST_PATH)
    missing, tampered = honeypots.verify()
    if missing:
        alerter.emit(f"{len(missing)} honeypot canary file(s) missing (deleted?): {missing[:3]}", "HIGH")
    if tampered:
        alerter.emit(f"{len(tampered)} honeypot canary file(s) tampered: {tampered[:3]}", "CRITICAL")
    if honeypots.manifest and not (missing or tampered):
        alerter.emit(f"{len(honeypots.manifest)} honeypot canaries armed.", "INFO")

    detector = Detector(config, alerter)
    fs = FileSystemMonitor(config, alerter, honeypots)
    proc_mon = ProcessMonitor(config, alerter)
    res_mon = ResourceMonitor(config, alerter)

    stop = threading.Event()

    def fs_loop():
        while not stop.is_set():
            try:
                detector.handle_scan(fs.classify_batch())
            except Exception as exc:
                alerter.emit(f"filesystem scan error: {exc}", "WARN")
            stop.wait(config.scan_interval)

    def proc_loop():
        interval = max(config.scan_interval, 3.0)
        while not stop.is_set():
            try:
                detector.handle_events(proc_mon.sample())
            except Exception as exc:
                alerter.emit(f"process scan error: {exc}", "WARN")
            stop.wait(interval)

    def res_loop():
        interval = max(config.scan_interval, 2.0)
        while not stop.is_set():
            try:
                detector.handle_events(res_mon.sample())
            except Exception as exc:
                alerter.emit(f"resource scan error: {exc}", "WARN")
            stop.wait(interval)

    threads = [
        threading.Thread(target=fs_loop, name="fs", daemon=True),
        threading.Thread(target=proc_loop, name="proc", daemon=True),
        threading.Thread(target=res_loop, name="res", daemon=True),
    ]
    for t in threads:
        t.start()

    alerter.emit(
        "RansomGuard active. Watching user data, critical system files, honeypots, "
        "processes and resources. Ctrl+C to stop.",
        "INFO",
    )

    def on_signal(*_):
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, on_signal)
        except (ValueError, OSError):
            pass

    try:
        while not stop.is_set():
            stop.wait(1.0)
    except KeyboardInterrupt:
        stop.set()
    finally:
        for t in threads:
            t.join(timeout=2)
        print("\nRansomGuard stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="RansomGuard - ransomware early-warning monitor")
    parser.add_argument("--config", type=str, help="path to config.json (default: ./config.json)")
    parser.add_argument("--setup-honeypots", action="store_true", help="plant canary decoy files")
    parser.add_argument("--remove-honeypots", action="store_true", help="remove canary decoy files")
    parser.add_argument("--scan-once", action="store_true", help="print prioritized inventory and exit")
    parser.add_argument("--check-config", action="store_true", help="validate config and exit")
    parser.add_argument("--freeze-now", action="store_true", help="emergency: suspend suspicious processes")
    args = parser.parse_args()

    cfg_path = Path(args.config) if args.config else CONFIG_PATH
    if not cfg_path.exists():
        write_default_config(cfg_path)
        print(f"Created default config at {cfg_path}. Edit it to match your machine, then rerun.")

    config = load_config(cfg_path)

    if args.setup_honeypots:
        cmd_setup_honeypots(config)
    elif args.remove_honeypots:
        cmd_remove_honeypots(config)
    elif args.scan_once:
        cmd_scan_once(config)
    elif args.check_config:
        cmd_check_config(config)
    elif args.freeze_now:
        cmd_freeze_now(config)
    else:
        run(config)


if __name__ == "__main__":
    main()
