"""Honeypot / canary file management.

Decoy files are planted in monitored directories with an innocuous-looking name
and a known content marker. Legitimate applications never touch them, so any
modification, deletion, or rename is a near-certain sign of automated mass
file processing (i.e. ransomware) or an intruder.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

MARKER_PREFIX = "HONEYPOT-CANARY-"


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
        return {os.path.normcase(v) for v in self.manifest.values()}

    def is_honeypot(self, path: str) -> bool:
        return os.path.normcase(path) in self.planted_paths()

    def setup(self) -> list[str]:
        created = []
        prefix = self.config.honeypot_prefix
        for spec in self.config.honeypot_dirs:
            base = Path(os.path.expandvars(os.path.expanduser(spec["path"])))
            if not base.is_dir():
                continue
            count = int(spec.get("count", 2))
            for i in range(count):
                name = f"{prefix}{uuid.uuid4().hex[:10]}_{i}.docx"
                target = base / name
                marker = MARKER_PREFIX + uuid.uuid4().hex
                try:
                    target.write_text(
                        "Invoice summary and Q4 forecast references.\n" + marker,
                        encoding="utf-8",
                    )
                    self.manifest[str(target)] = marker
                except OSError:
                    continue
        self._save()
        created = [p for p in self.manifest]
        return created

    def verify(self) -> tuple[list[str], list[str]]:
        missing = []
        tampered = []
        for path, marker in list(self.manifest.items()):
            p = Path(path)
            if not p.exists():
                missing.append(path)
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                if marker not in content:
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
