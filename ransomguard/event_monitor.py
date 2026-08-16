"""Event-driven change watcher (watchdog) to trigger scans on demand.

Falls back to nothing if watchdog isn't installed; the main loop then just polls
at `scan_interval`. When present, any filesystem change in a watched directory
wakes the loop immediately, so detection latency drops from "next poll" to
"next change".
"""
from __future__ import annotations

import os
import threading

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

EVENT_TYPES = {"created", "modified", "moved", "deleted"}


class _Handler(FileSystemEventHandler):
    def __init__(self, trigger: threading.Event):
        self.trigger = trigger

    def on_any_event(self, event):
        self.trigger.set()


class EventMonitor:
    def __init__(self, config):
        self.config = config
        self._observer = None
        self._trigger = threading.Event()

    def start(self) -> bool:
        if not self.config.event_driven:
            return False
        try:
            from watchdog.observers import Observer  # noqa: F401
        except ImportError:
            return False
        self._observer = Observer()
        watched = set()
        for d in self.config.watch_dirs:
            root = os.path.expandvars(os.path.expanduser(d["path"]))
            if root and root not in watched and os.path.isdir(root):
                self._observer.schedule(_Handler(self._trigger), root, recursive=bool(d.get("recursive", True)))
                watched.add(root)
        self._observer.daemon = True
        self._observer.start()
        return True

    def wait(self, timeout: float) -> bool:
        """Block until a change event or timeout; returns True if a change occurred."""
        return self._trigger.wait(timeout)

    def consume(self) -> None:
        self._trigger.clear()

    def stop(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)
