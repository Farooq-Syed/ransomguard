"""System resource monitoring: CPU, memory, disk I/O spikes."""
from __future__ import annotations

import time

import psutil


class ResourceMonitor:
    def __init__(self, config, alerter):
        self.config = config.resource
        self.alerter = alerter
        self._last_disk = None
        self._last_time = None

    def sample(self) -> list[dict]:
        events = []
        cfg = self.config
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
        except (psutil.Error, OSError):
            return events

        if cpu >= int(cfg.get("cpu_spike_percent", 80)):
            events.append({"type": "resource", "kind": "cpu_spike", "weight": 15, "value": cpu})
        if mem >= int(cfg.get("mem_threshold_percent", 90)):
            events.append({"type": "resource", "kind": "memory", "weight": 20, "value": mem})

        try:
            disk = psutil.disk_io_counters()
        except (psutil.Error, OSError):
            disk = None
        if disk:
            now = time.time()
            if self._last_disk and self._last_time:
                elapsed = now - self._last_time
                if elapsed > 0:
                    write_mbps = (disk.write_bytes - self._last_disk.write_bytes) / (1024 * 1024) / elapsed
                    threshold = int(cfg.get("disk_write_mbps_threshold", 300))
                    if write_mbps >= threshold:
                        events.append(
                            {"type": "resource", "kind": "disk_write", "weight": 35, "value": write_mbps}
                        )
            self._last_disk = disk
            self._last_time = now
        return events
