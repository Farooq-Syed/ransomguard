"""Emergency response actions, dry-run safe by default.

Actions are logged even in dry-run so operators see exactly what *would* have
happened. In `active` mode the configured actions are executed.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None


class Responder:
    def __init__(self, config, alerter, mode: str = "dry-run"):
        self.config = config
        self.alerter = alerter
        self.mode = mode
        self._vss_count = None
        self._shadow_checked = False

    def _act(self, description: str) -> None:
        if self.mode == "dry-run":
            self.alerter.emit(f"[DRY-RUN] would execute: {description}", "WARN")
        else:
            self.alerter.emit(f"[RESPONDER] executing: {description}", "CRITICAL")

    def respond(self, level: str, details: list[str], procs: list[dict] | None = None) -> None:
        if level not in ("CRITICAL", "PANDEMIC"):
            return
        cfg = self.config.responder
        if cfg.get("kill_suspicious"):
            self.kill_suspicious(procs or [])
        if cfg.get("disable_shares"):
            self.disable_shares()
        self.check_shadow_copies()

    def kill_suspicious(self, procs: list[dict]) -> None:
        if psutil is None:
            return
        names = {p.get("name", "").lower() for p in procs if p.get("kind") in ("shadowcopy", "suspicious_binary", "mass_writer")}
        names |= {n.lower() for n in self.config.suspicious_names}
        killed = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info.get("name") or "").lower()
            except psutil.Error:
                continue
            if pname in names:
                desc = f"suspend/kill process {proc.info.get('name')} pid={proc.info.get('pid')}"
                self._act(desc)
                if self.mode == "active":
                    try:
                        proc.suspend()
                        killed.append((proc.info.get("name"), proc.info.get("pid")))
                    except (psutil.Error, OSError) as exc:
                        self.alerter.emit(f"failed to suspend {proc.info.get('name')}: {exc}", "WARN")
        if killed:
            self.alerter.emit(f"Suspended {len(killed)} suspicious process(es).", "CRITICAL")

    def disable_shares(self) -> None:
        if os.name != "nt":
            return
        try:
            out = subprocess.run(["net", "share"], capture_output=True, text=True, timeout=10)
            shares = [ln.split()[0] for ln in out.stdout.splitlines() if ln.startswith("Share name")]
        except (OSError, subprocess.SubprocessError):
            return
        for share in shares:
            share = share.strip().lstrip("*")
            desc = f"remove network share '{share}' (requires admin)"
            self._act(desc)
            if self.mode == "active":
                try:
                    subprocess.run(["net", "share", share, "/delete", "/y"],
                                   capture_output=True, timeout=10)
                    self.alerter.emit(f"Network share '{share}' removed.", "CRITICAL")
                except (OSError, subprocess.SubprocessError):
                    pass

    def check_shadow_copies(self) -> None:
        if os.name != "nt":
            return
        try:
            out = subprocess.run(["vssadmin", "list", "shadows"],
                                 capture_output=True, text=True, timeout=20)
            count = out.stdout.lower().count("shadow copy id")
        except (OSError, subprocess.SubprocessError):
            return
        self._shadow_checked = True
        if self._vss_count is not None and count < self._vss_count:
            self.alerter.emit(
                f"Volume Shadow Copies dropped from {self._vss_count} to {count} — "
                "backup copies may be under attack.",
                "CRITICAL",
            )
        self._vss_count = count

    def snapshot_before_quarantine(self, source: str) -> Path | None:
        """Copy a file to the safe store *before* it is moved out of place."""
        qdir = self.config.quarantine_dir
        if not qdir:
            return None
        try:
            qdir.mkdir(parents=True, exist_ok=True)
            src = Path(source)
            target = qdir / src.name
            n = 1
            while target.exists():
                target = qdir / f"{src.stem}_{n}{src.suffix}"
                n += 1
            shutil.copy2(source, str(target))
            return target
        except OSError:
            return None
