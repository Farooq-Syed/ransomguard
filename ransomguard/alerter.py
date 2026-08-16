"""Alerting: colored console output, rotating log file, optional webhook POST."""
from __future__ import annotations

import json
import logging
import time
import urllib.request
from pathlib import Path

LEVELS = {
    "INFO": 20,
    "WARN": 30,
    "HIGH": 35,
    "CRITICAL": 40,
    "PANDEMIC": 50,
}

COLORS = {
    "INFO": "\033[32m",
    "WARN": "\033[33m",
    "HIGH": "\033[35m",
    "CRITICAL": "\033[91m",
    "PANDEMIC": "\033[41;37m",
}
RESET = "\033[0m"


class Alerter:
    def __init__(self, log_file: str = "ransomguard.log", webhook_url: str = ""):
        self._logger = logging.getLogger("ransomguard")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        if log_file:
            try:
                handler = logging.FileHandler(log_file, encoding="utf-8")
                handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
                self._logger.addHandler(handler)
            except OSError:
                pass
        self.webhook = webhook_url
        self._seen = {}
        self._cooldown = 30.0

    def emit(self, message: str, level: str = "INFO", dedup_key: str | None = None) -> None:
        if dedup_key:
            now = time.time()
            last = self._seen.get(dedup_key, 0.0)
            if now - last < self._cooldown:
                return
            self._seen[dedup_key] = now
        color = COLORS.get(level, "")
        print(f"{color}[{level:^8}]{RESET} {message}")
        self._logger.log(LEVELS.get(level, 20), message)
        if self.webhook and level in ("HIGH", "CRITICAL", "PANDEMIC"):
            self._post_webhook(message, level)

    def _post_webhook(self, message: str, level: str) -> None:
        payload = json.dumps({"text": f"[{level}] {message}", "ts": int(time.time())}).encode()
        req = urllib.request.Request(
            self.webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
