"""RansomGuard - ransomware early-warning monitor.

Usage:
  python main.py                            start continuous monitoring (event-driven + polling)
  python main.py --setup-honeypots          plant decoy canary files
  python main.py --scan-once                one-shot prioritized inventory report
  python main.py --check-config             validate configuration and exit
  python main.py --freeze-now               emergency: suspend suspicious processes
  python main.py --restore <quarantine_dir> move quarantined files back
  python main.py --add-mapped-drives        add network drives to the watch list
  python main.py --responder active|dry-run responder mode for emergency actions
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ransomguard.alerter import Alerter
from ransomguard.config import load_config, validate, write_default_config
from ransomguard.detector import Detector
from ransomguard.event_monitor import EventMonitor
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager
from ransomguard.process_monitor import ProcessMonitor
from ransomguard.responder import Responder
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
    print(f"entropy_chunks:     {config.entropy_chunks}")
    print(f"rate warn/critical: {config.rate_warn}/{config.rate_critical} per {config.rate_window}s")
    print(f"hash_tracking:      {'on' if config.hash_tracked else 'off'} (max {config.hash_track_max_files} files)")
    print(f"event_driven:       {config.event_driven}")
    print(f"auto_freeze:        {config.auto_freeze}")
    print(f"quarantine_dir:     {config.quarantine_dir}")
    print(f"webhook:            {'configured' if config.webhook_url else 'disabled'}")
    print(f"cef_log_file:       {config.cef_log_file or 'disabled'}")
    resp = config.responder
    print(f"responder config:   dry_run={resp.get('dry_run', True)} kill_suspicious={resp.get('kill_suspicious', True)} disable_shares={resp.get('disable_shares', False)}")
    print(f"watch_dirs:         {len(config.watch_dirs)}")
    print(f"watch_files:        {len(config.watch_files)}")
    missing = [d["path"] for d in config.watch_dirs if not os.path.isdir(os.path.expandvars(os.path.expanduser(d["path"])))]
    if missing:
        print("NOTE: missing watch dirs (ignored at runtime):")
        for m in missing:
            print(f"  {m}")
    issues = validate(config._d)
    if issues:
        print("\nCONFIG ISSUES:")
        for i in issues:
            print(f"  ! {i}")
    else:
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


def cmd_restore(quarantine_dir: str) -> None:
    q = Path(quarantine_dir)
    if not q.is_dir():
        print(f"Quarantine dir not found: {q}")
        return
    restored = 0
    for f in q.iterdir():
        if not f.is_file():
            continue
        target = Path.home() / f.name
        n = 1
        while target.exists():
            target = Path.home() / f"{f.stem}_{n}{f.suffix}"
            n += 1
        os.replace(str(f), str(target))
        print(f"Restored {f.name} -> {target}")
        restored += 1
    print(f"Restored {restored} file(s). Review each one before use.")


def cmd_add_mapped_drives(config, cfg_path: Path) -> None:
    try:
        import psutil
    except ImportError:
        print("psutil required.")
        return
    net_drives = []
    try:
        for part in psutil.disk_partitions(all=True):
            fstype = (part.fstype or "").lower()
            if fstype in ("network", "nfs", "cifs", "smbfs", "smb") or part.mountpoint.startswith("\\\\"):
                net_drives.append({"path": part.mountpoint.replace("\\", "/"), "priority": 60, "recursive": True})
    except (psutil.Error, OSError) as exc:
        print(f"Could not enumerate drives: {exc}")
        return
    if not net_drives:
        print("No network/mapped drives found to add.")
        return
    existing = {d["path"] for d in config.watch_dirs}
    added = [d for d in net_drives if d["path"] not in existing]
    if not added:
        print("All network drives already watched.")
        return
    data = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    data.setdefault("watch_dirs", []).extend(added)
    cfg_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Added {len(added)} network drive(s) to watch_dirs in {cfg_path}:")
    for d in added:
        print(f"  {d['path']}")


def run(config, config_path: Path, responder_mode: str) -> None:
    alerter = Alerter(
        log_file=str(ROOT / config.log_file),
        webhook_url=config.webhook_url,
        cef_log_file=config.cef_log_file or "",
    )
    honeypots = HoneypotManager(config, MANIFEST_PATH)
    missing, tampered = honeypots.verify()
    if missing:
        alerter.emit(f"{len(missing)} honeypot canary file(s) missing (deleted?): {missing[:3]}", "HIGH")
    if tampered:
        alerter.emit(f"{len(tampered)} honeypot canary file(s) tampered: {tampered[:3]}", "CRITICAL")
    if honeypots.manifest and not (missing or tampered):
        alerter.emit(f"{len(honeypots.manifest)} honeypot canaries armed.", "INFO")

    responder = Responder(config, alerter, mode=responder_mode)
    detector = Detector(config, alerter, responder=responder)
    fs = FileSystemMonitor(config, alerter, honeypots)
    proc_mon = ProcessMonitor(config, alerter)
    res_mon = ResourceMonitor(config, alerter)
    event_mon = EventMonitor(config)
    event_on = event_mon.start()
    if event_on:
        alerter.emit("Event-driven watching enabled (watchdog); scans trigger on change.", "INFO")

    stop = threading.Event()
    last_cfg_mtime = config_path.stat().st_mtime_ns if config_path.exists() else 0

    def fs_loop():
        nonlocal last_cfg_mtime
        while not stop.is_set():
            try:
                batch = fs.classify_batch()
                writers = proc_mon.attribute(batch) if batch.get("status") != "baseline" else []
                detector.handle_scan(batch, writers=writers)
            except Exception as exc:
                alerter.emit(f"filesystem scan error: {exc}", "WARN")
            if event_on:
                event_mon.consume()
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

    def reload_loop():
        nonlocal last_cfg_mtime
        while not stop.is_set():
            stop.wait(5.0)
            if not config_path.exists():
                continue
            mtime = config_path.stat().st_mtime_ns
            if mtime != last_cfg_mtime:
                last_cfg_mtime = mtime
                issues = config.reload_from(config_path)
                alerter.emit("Configuration hot-reloaded.", "INFO")
                for i in issues:
                    alerter.emit(f"config issue: {i}", "WARN")

    threads = [
        threading.Thread(target=fs_loop, name="fs", daemon=True),
        threading.Thread(target=proc_loop, name="proc", daemon=True),
        threading.Thread(target=res_loop, name="res", daemon=True),
        threading.Thread(target=reload_loop, name="cfg", daemon=True),
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
        event_mon.stop()
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
    parser.add_argument("--restore", type=str, metavar="DIR", help="move quarantined files back from DIR")
    parser.add_argument("--add-mapped-drives", action="store_true", help="add network drives to watch list")
    parser.add_argument("--responder", choices=["dry-run", "active"], default="dry-run",
                        help="responder mode for emergency actions (default: dry-run)")
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
    elif args.restore:
        cmd_restore(args.restore)
    elif args.add_mapped_drives:
        cmd_add_mapped_drives(config, cfg_path)
    else:
        run(config, cfg_path, args.responder)


if __name__ == "__main__":
    main()
