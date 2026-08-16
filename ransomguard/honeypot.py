"""Honeypot / canary file management.

Decoy files are planted in monitored directories with an innocuous, randomized
name and a known content marker. Legitimate applications never touch them, so any
modification, deletion, or rename is a near-certain sign of automated mass file
processing (i.e. ransomware) or an intruder.

Names are randomized and drawn from realistic-looking pools (no fixed "~canary_"
prefix) so ransomware cannot fingerprint and pre-delete them. Optionally some
decoys are planted already-partially-encrypted ("bait") so malware that skips
files it believes are mid-encryption still trips the canary.
"""
from __future__ import annotations

import json
import os
import random
import uuid
from pathlib import Path

MARKER_PREFIX = "HONEYPOT-CANARY-"

NAME_POOL = [
    "invoices_{}.xlsx", "budget_final_{}.docx", "backup_archive_{}.zip",
    "client_contracts_{}.pdf", "passwords_backup_{}.txt", "q4_financials_{}.xlsx",
    "project_notes_{}.docx", "meeting_minutes_{}.txt", "database_export_{}.sql",
    "photos_{}.zip", "tax_records_{}.pdf", "ssh_keys_{}.bak", "database_backup_{}.db",
]

BAIT_EXTENSIONS = [".docx", ".xlsx", ".pdf", ".zip"]  # reserved for future bait styles


class HoneypotManager:
    def __init__(self, config, manifest_path: Path):
        self.config = config
        self.manifest_path = manifest_path
        self.manifest: dict = {}
        self._load()

    def _load(self) -> None:
        if self.manifest_path.exists():
            try:
                self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.manifest = {}

    def _save(self) -> None:
        try:
            self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
            self.manifest_path.write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")
        except OSError:
            pass

    def planted_paths(self) -> set[str]:
        return {os.path.normcase(p) for p in self.manifest}

    def is_honeypot(self, path: str) -> bool:
        return os.path.normcase(path) in self.planted_paths()

    def setup(self, rng: random.Random | None = None) -> list[str]:
        rng = rng or random.Random()
        existing = self.planted_paths()
        for spec in self.config.honeypot_dirs:
            base = Path(os.path.expandvars(os.path.expanduser(spec["path"])))
            if not base.is_dir():
                continue
            count = int(spec.get("count", 2))
            for i in range(count):
                marker = MARKER_PREFIX + uuid.uuid4().hex
                name = self._random_name(rng)
                target = base / name
                n = 1
                while target.exists() or os.path.normcase(str(target)) in existing:
                    name = self._random_name(rng)
                    target = base / name
                    n += 1
                    if n > 50:
                        break
                try:
                    self._write_canary(target, marker)
                    self.manifest[str(target)] = marker
                except OSError:
                    continue
        self._save()
        return [p for p in self.manifest]

    def _random_name(self, rng: random.Random) -> str:
        return rng.choice(NAME_POOL).format(rng.randrange(100000))

    def _write_canary(self, target: Path, marker: str) -> None:
        bait = self.config.honeypot_bait and random.Random().random() < 0.5
        if bait:
            payload = os.urandom(4096) + marker.encode() + b"\n"
        else:
            payload = b"Quarterly report, budget forecasts, invoice records.\n" + marker.encode() + b"\n"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    def verify(self) -> tuple[list[str], list[str]]:
        missing = []
        tampered = []
        for path, marker in list(self.manifest.items()):
            p = Path(path)
            if not p.exists():
                missing.append(path)
                continue
            try:
                content = p.read_bytes()
                if marker.encode() not in content:
                    tampered.append(path)
            except OSError:
                tampered.append(path)
        return missing, tampered

    def remove(self) -> None:
        for path in list(self.manifest):
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        self.manifest = {}
        self._save()
