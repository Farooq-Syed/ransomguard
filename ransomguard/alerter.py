"""Alerting: colored console output, rotating log file, CEF export, optional webhook POST."""
from __future__ import annotations

import json
import logging
import socket
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

CEF_SEVERITY = {"INFO": 3, "WARN": 5, "HIGH": 7, "CRITICAL": 9, "PANDEMIC": 10}

COLORS = {
    "INFO": "\033[32m",
    "WARN": "\033[33m",
    "HIGH": "\033[35m",
    "CRITICAL": "\033[91m",
    "PANDEMIC": "\033[41;37m",
}
RESET = "\033[0m"


def _cef_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", "\\n")


class Alerter:
    def __init__(self, log_file: str = "ransomguard.log", webhook_url: str = "",
                 cef_log_file: str = ""):
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
        self.cef_log_file = cef_log_file
        self._seen = {}
        self._cooldown = 30.0
        try:
            self._host = socket.gethostname()
        except OSError:
            self._host = "unknown"

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
        self._emit_cef(message, level)
        if self.webhook and level in ("HIGH", "CRITICAL", "PANDEMIC"):
            self._post_webhook(message, level)

    def _emit_cef(self, message: str, level: str) -> None:
        if not self.cef_log_file:
            return
        line = (
            f"CEF:0|RansomGuard|RansomGuard|1.0|100|Ransomware Detection|{CEF_SEVERITY.get(level, 5)}|"
            f"act=notify msg={_cef_escape(message)} suser={_cef_escape(self._host)} rt={int(time.time())}"
        )
        try:
            with open(self.cef_log_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    def _post_webhook(self, message: str, level: str) -> None:
        payload = json.dumps({"text": f"[{level}] {message}", "ts": int(time.time())}).encode()
        req = urllib.request.Request(
            self.webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        for attempt in range(3):
            try:
                urllib.request.urlopen(req, timeout=5)
                return
            except Exception:
                if attempt < 2:
                    time.sleep(1.0 * (attempt + 1))
        self._logger.warning("webhook delivery failed after retries: %s", self.webhook)
