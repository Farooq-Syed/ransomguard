"""Detection engine: scores raw events, tracks modification rates, raises alerts."""
from __future__ import annotations

import os
import shutil
import time
from collections import deque
from pathlib import Path

from . import utils
from .alerter import Alerter

NEW_FILE_TARGET = 20
NEW_FILE_HIGH_VALUE = 30
NEW_FILE_NOTE = 60
NEW_FILE_APPENDED_EXT = 45
MODIFIED_TARGET = 15
MODIFIED_MAGIC_CHANGE = 40
MODIFIED_HIGH_ENTROPY = 30
MODIFIED_AGED = 25
RENAME_EXT_CHANGE = 40
DELETE_TARGET = 10
HONEYPOT_HIT = 120
RATE_WARN = 15
RATE_CRITICAL = 40
IN_HIGH_PRIORITY_DIR = 15
CRITICAL_FILE = 25


class Detector:
    def __init__(self, config, alerter: Alerter):
        self.config = config
        self.alerter = alerter
        self._mod_events: deque[float] = deque()
        self._last_level = "INFO"
        self._last_freeze_time = 0.0

    def _priority_for(self, path: str) -> int:
        pri = self.config.file_priority(path)
        if pri:
            return pri
        for d in self.config.watch_dirs:
            root = os.path.normcase(os.path.expandvars(os.path.expanduser(d["path"])))
            if os.path.normcase(path).startswith(root + os.sep) or os.path.normcase(path).startswith(root + "/"):
                return int(d.get("priority", 50))
        return 30

    def _rate(self) -> int:
        now = time.time()
        cutoff = now - self.config.rate_window
        while self._mod_events and self._mod_events[0] < cutoff:
            self._mod_events.popleft()
        return len(self._mod_events)

    def handle_scan(self, batch: dict) -> None:
        if batch.get("status") == "baseline":
            self.alerter.emit(f"Baseline snapshot taken: {batch['files']} files tracked.", "INFO")
            return

        score = 0
        details = []
        strong = False

        for entry in batch["modified"]:
            path = entry.path
            priority = self._priority_for(path)
            if priority >= 90:
                score += CRITICAL_FILE + 5
                strong = True
                details.append(f"critical system file modified: {path}")
            entropy = utils.sample_entropy(path, self.config.entropy_sample)
            new_magic = utils.detect_magic(path)
            ext = entry.ext

            self._mod_events.append(time.time())

            if utils.classify_magic_change(entry.magic, new_magic):
                score += MODIFIED_MAGIC_CHANGE
                strong = True
                details.append(f"file overwritten/content-type change: {path} ({entry.magic}->{new_magic})")
            if entropy >= self.config.entropy_threshold:
                score += MODIFIED_HIGH_ENTROPY
                strong = True
                details.append(f"high entropy {entropy:.2f} (likely encrypted): {path}")
            if utils.is_target_ext(ext):
                score += MODIFIED_TARGET
            if utils.is_high_value_ext(ext):
                score += MODIFIED_TARGET + 10
            if self._age_days(entry) > self.config.aged_days:
                score += self.config.aged_score
                details.append(f"aged file ({self._age_days(entry):.0f} days old) suddenly modified: {path}")

        for entry in batch["new"]:
            base = os.path.basename(entry.path)
            priority = self._priority_for(entry.path)
            self._mod_events.append(time.time())
            appended = utils.is_known_ransomware_ext(base)
            if appended:
                score += NEW_FILE_APPENDED_EXT
                strong = True
                details.append(f"ransom-style appended extension '{appended}': {entry.path}")
            if utils.looks_like_ransom_note(base, self.config.note_patterns):
                score += NEW_FILE_NOTE
                strong = True
                details.append(f"possible ransom note created: {entry.path}")
            if priority >= 90:
                score += NEW_FILE_HIGH_VALUE
                strong = True
            if utils.is_target_ext(entry.ext):
                score += NEW_FILE_TARGET
            if utils.is_high_value_ext(entry.ext):
                score += NEW_FILE_HIGH_VALUE

        for path, added in batch["renamed"]:
            score += RENAME_EXT_CHANGE
            strong = True
            details.append(f"extension change (rename) {os.path.basename(path)} -> {added}")

        for entry in batch["deleted"]:
            if utils.is_target_ext(entry.ext) or entry.ext in ("exe", "dll"):
                score += DELETE_TARGET
                details.append(f"deleted: {entry.path}")

        for entry in batch["honeypot_hits"]:
            score += HONEYPOT_HIT
            strong = True
            details.append(f"HONEYPOT touched: {entry.path}")

        rate = self._rate()
        if rate >= self.config.rate_critical:
            score += RATE_CRITICAL
            strong = True
            details.append(f"mass modification rate {rate}/min (critical)")
        elif rate >= self.config.rate_warn:
            score += RATE_WARN
            details.append(f"elevated modification rate {rate}/min")

        if strong and score >= 150:
            self._escalate("PANDEMIC", score, details)
        elif strong and score >= 80:
            self._escalate("CRITICAL", score, details)
        elif strong and score >= 40:
            self._escalate("HIGH", score, details)
        elif score >= 40:
            self._escalate("WARN", score, details)
        elif score >= 15:
            self.alerter.emit(
                f"Low-suspicion activity (score {score}): " + " | ".join(details[:2]),
                "WARN",
                dedup_key="fs:low",
            )

    @staticmethod
    def _age_days(entry) -> float:
        return (time.time() - entry.mtime_ns / 1e9) / 86400.0

    def handle_events(self, events: list[dict]) -> None:
        score = 0
        details = []
        for ev in events:
            kind = ev.get("kind")
            weight = ev.get("weight", 0)
            score += weight
            if kind == "shadowcopy":
                details.append(
                    f"shadow-copy deletion attempt: {ev.get('name')} [{ev.get('pid')}] {ev.get('cmdline', '')[:120]}"
                )
            elif kind == "suspicious_binary":
                details.append(f"suspicious tool running: {ev.get('name')} [{ev.get('pid')}]")
            elif kind == "suspicious_location":
                details.append(f"process from suspicious path: {ev.get('exe')}")
            elif kind == "mass_writer":
                details.append(f"process writing heavily: {ev.get('name')} [{ev.get('pid')}]")
            elif kind == "cpu_spike":
                details.append(f"CPU spike {ev.get('value')}%")
            elif kind == "memory":
                details.append(f"memory pressure {ev.get('value')}%")
            elif kind == "disk_write":
                details.append(f"disk write burst {ev.get('value'):.0f} MB/s")
        if details:
            self._escalate_events(score, details)

    def _escalate(self, level: str, score: int, details: list[str]) -> None:
        shown = details[:6]
        extra = f" (+{len(details) - len(shown)} more signals)" if len(details) > len(shown) else ""
        msg = f"Suspect score {score} | " + " | ".join(shown[:3]) + extra
        self.alerter.emit(msg, level, dedup_key=f"fs:{level}")
        if level in ("CRITICAL", "PANDEMIC"):
            self._maybe_quarantine(details)
            if self.config.auto_freeze:
                self._freeze()

    def _escalate_events(self, score: int, details: list[str]) -> None:
        level = "HIGH" if score >= 40 else "WARN"
        msg = f"Process/resource score {score} | " + " | ".join(details[:3])
        self.alerter.emit(msg, level, dedup_key=f"ev:{level}")

    def _maybe_quarantine(self, details: list[str]) -> None:
        qdir = self.config.quarantine_dir
        if not qdir:
            return
        try:
            qdir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return
        moved = 0
        for d in details:
            if ":" not in d:
                continue
            path = d.split(": ", 1)[-1].split(" (")[0].strip()
            if not path or not os.path.isfile(path):
                continue
            target = qdir / Path(path).name
            n = 1
            while target.exists():
                target = qdir / f"{Path(path).stem}_{n}{Path(path).suffix}"
                n += 1
            try:
                shutil.move(path, str(target))
                self.alerter.emit(f"Quarantined suspicious file: {path} -> {target}", "CRITICAL")
                moved += 1
            except OSError as exc:
                self.alerter.emit(f"Quarantine failed for {path}: {exc}", "WARN")
        if moved:
            self.alerter.emit(
                f"Ransomware suspected. {moved} suspicious file(s) quarantined to {qdir}. "
                "Disconnect from network, kill the offending process, restore from offline backups.",
                "PANDEMIC",
            )
