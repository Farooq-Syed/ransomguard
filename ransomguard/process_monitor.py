"""Process-level monitoring: shadow-copy deletion, suspicious binaries, mass writers."""
from __future__ import annotations

import os
import time

import psutil

SUSPICIOUS_DIR_PARTS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\windows\\temp",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]


class ProcessMonitor:
    def __init__(self, config, alerter):
        self.config = config
        self.alerter = alerter
        self._known_pids = set()
        self._io = {}
        self._ready = False

    def _iter(self):
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
            try:
                yield p.info
            except psutil.Error:
                continue

    def sample(self) -> list[dict]:
        events = []
        try:
            procs = list(self._iter())
        except psutil.Error:
            return events
        pids = set()
        now = time.time()
        for info in procs:
            pid = info["pid"]
            pids.add(pid)
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or []).lower()
            reasons = []

            low_cmd = cmdline
            for pat in self.config.shadowcopy_patterns:
                if pat in low_cmd or pat in name:
                    reasons.append(("shadowcopy", 70))
                    break

            if name in self.config.suspicious_names:
                reasons.append(("suspicious_binary", 45))

            if exe:
                low_exe = exe.lower().replace("/", "\\")
                for part in SUSPICIOUS_DIR_PARTS:
                    if part in low_exe:
                        reasons.append(("suspicious_location", 30))
                        break

            if not self._ready:
                continue

            if pid not in self._known_pids:
                reasons.append(("new_process", 5))

            if exe:
                try:
                    io = psutil.Process(pid).io_counters()
                    prev = self._io.get(pid)
                    self._io[pid] = (io.write_bytes, io.write_chars if hasattr(io, "write_chars") else 0, now)
                    if prev is not None:
                        elapsed = now - prev[2]
                        if elapsed > 0:
                            mbps = (io.write_bytes - prev[0]) / (1024 * 1024) / elapsed
                            if mbps > 300:
                                reasons.append(("mass_writer", 40))
                except (psutil.Error, OSError):
                    pass

            if reasons:
                for kind, weight in reasons:
                    events.append(
                        {
                            "type": "process",
                            "kind": kind,
                            "weight": weight,
                            "name": info.get("name"),
                            "pid": pid,
                            "exe": exe,
                            "cmdline": " ".join(info.get("cmdline") or []),
                        }
                    )
        self._known_pids = pids
        self._io = {pid: v for pid, v in self._io.items() if pid in pids}
        self._ready = True
        return events
