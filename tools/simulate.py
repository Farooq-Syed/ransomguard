"""Synthetic ransomware / benign workload simulator.

Drives real filesystem operations in a sandbox so detectors see the exact same
ground-truth activity (identical for v1 heuristic and v2 ML evaluation).
"""
from __future__ import annotations

import os
import random
import shutil
import time
from pathlib import Path

LOW_ENTROPY_TEXT = "Quarterly report, budget forecasts, invoice records, project notes.\n" * 40
LOW_ENTROPY_BINARY = b"\xff\xd8\xff\xe0" + bytes((i * 7) % 16 for i in range(4096))

EXT_POOL = ["docx", "xlsx", "pdf", "txt", "csv", "png", "jpg", "mp4", "sqlite"]
RANSOM_EXTS = [".lockbit", ".crypt", ".encrypted", ".ryuk", ".conti", ".locked", ".enc"]
NOTE_NAMES = [
    "README_RESTORE.txt",
    "HOW_TO_DECRYPT.txt",
    "!read_me_medusa!!.txt",
    "RyukReadMe.txt",
    "restore-files.html",
]
NOVEL_RANSOM_EXTS = [".pandora", ".fl00d", ".zzap", ".winterfell", ".cipherx"]
NOVEL_NOTE_NAMES = ["RECOVER_YOUR_DATA.txt", "ENCRYPTION_ALERT.html", "restore_your_files.txt", "HALT.txt"]
SUBDIRS = ["docs", "data", "backup", "archive", "misc", "images"]


class Sandbox:
    def __init__(self, root: str, n_files: int = 40, rng: random.Random | None = None,
                 noise: float = 0.0, attack_style: str = "classic"):
        self.root = Path(root)
        self.rng = rng or random.Random()
        self.noise = noise
        self.attack_style = attack_style
        self._counter = 0
        self.files: list[str] = []
        self.aged_files: list[str] = []
        self.n_created = 0
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        for i in range(n_files):
            rel = self._new_rel_path()
            self._write(rel, high_entropy=False)
            self.files.append(rel)
            if i % 7 == 0:
                past = time.time() - 400 * 86400
                os.utime(self.root / rel, (past, past))
                self.aged_files.append(rel)

    def _new_rel_path(self) -> str:
        self._counter += 1
        sub = self.rng.choice(SUBDIRS)
        ext = self.rng.choice(EXT_POOL)
        return f"{sub}/file_{self._counter:05d}.{ext}"

    def _write(self, rel: str, high_entropy: bool, size: int | None = None) -> None:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if high_entropy:
            size = size or self.rng.randrange(1024, 8192)
            p.write_bytes(os.urandom(size))
        else:
            if p.suffix.lower() in (".docx", ".txt", ".csv", ".pdf", ".sqlite"):
                p.write_bytes(LOW_ENTROPY_TEXT.encode()[: max(256, size or 2048)])
            else:
                p.write_bytes((LOW_ENTROPY_BINARY[: max(256, size or 4096)]))

    def benign_step(self, rng: random.Random) -> list[dict]:
        for _ in range(rng.randrange(2, 5)):
            if self.files:
                rel = rng.choice(self.files)
                self._write(rel, high_entropy=False, size=2048)
        for _ in range(rng.randrange(1, 3)):
            rel = self._new_rel_path()
            self._write(rel, high_entropy=False)
            self.files.append(rel)
            self.n_created += 1
        if rng.random() < 0.3 and len(self.files) > 5:
            rel = rng.choice(self.files)
            try:
                (self.root / rel).unlink()
                self.files.remove(rel)
            except OSError:
                pass
        if self.noise > 0:
            if rng.random() < self.noise:
                rel = f"temp/download_{self._counter:05d}.tmp"
                self._write(rel, high_entropy=True, size=rng.randrange(4096, 65536))
                self.files.append(rel)
            if rng.random() < self.noise * 0.7:
                for _ in range(rng.randrange(50, 90)):
                    rel = self._new_rel_path()
                    self._write(rel, high_entropy=False)
                    self.files.append(rel)
                    self.n_created += 1
        return self._benign_system_events(rng)

    def attack_step(self, fraction: float, rng: random.Random, honeypots=None) -> list[dict]:
        style = self.attack_style
        targets = self.files[:]
        rng.shuffle(targets)
        k = max(1, int(len(targets) * fraction))
        targets = targets[:k]
        canary_paths = {str(p) for p in (honeypots.manifest if honeypots else {})}
        for rel in targets:
            norm = str(self.root / rel)
            if norm in canary_paths:
                continue
            size = (self.root / rel).stat().st_size or 2048
            if style == "wiper":
                p = self.root / rel
                try:
                    p.write_bytes(b"\x00" * size)  # low-entropy destructive overwrite
                except OSError:
                    pass
            else:
                self._write(rel, high_entropy=True, size=size)
        for rel in targets:
            if style in ("stealth", "wiper"):
                continue
            if rng.random() < 0.6:
                ext = rng.choice(NOVEL_RANSOM_EXTS if style == "novel_ext" else RANSOM_EXTS)
                try:
                    os.rename(self.root / rel, self.root / (rel + ext))
                    if rel in self.files:
                        self.files.remove(rel)
                        self.files.append(rel + ext)
                    if rel in self.aged_files:
                        self.aged_files.remove(rel)
                except OSError:
                    pass
        if honeypots:
            for path in canary_paths:
                p = Path(path)
                if p.exists():
                    try:
                        p.write_bytes(os.urandom(p.stat().st_size or 2048))
                    except OSError:
                        pass
        if style not in ("stealth", "wiper"):
            dirs = {str((self.root / os.path.dirname(f)).resolve()) for f in self.files}
            for d in dirs:
                try:
                    note = Path(d) / rng.choice(NOVEL_NOTE_NAMES if style == "novel_ext" else NOTE_NAMES)
                    note.write_text("Your files have been encrypted. Pay to recover.\n", encoding="utf-8")
                except OSError:
                    pass
            if rng.random() < 0.4:
                extra = targets[: max(1, len(targets) // 4)]
                for rel in extra:
                    p = self.root / rel
                    if p.exists():
                        try:
                            p.unlink()
                            if rel in self.files:
                                self.files.remove(rel)
                        except OSError:
                            pass
        if style == "wiper":
            for rel in targets:
                p = self.root / rel
                if p.exists() and rng.random() < 0.3:
                    try:
                        p.unlink()
                        if rel in self.files:
                            self.files.remove(rel)
                    except OSError:
                        pass
        return self._attack_system_events(rng)

    def step(self, window_idx: int, attack_start: int | None, honeypots, rng: random.Random) -> list[dict]:
        if attack_start is not None and window_idx >= attack_start:
            frac = min(0.9, 0.25 + 0.2 * (window_idx - attack_start))
            return self.attack_step(frac, rng, honeypots)
        return self.benign_step(rng)

    def _benign_system_events(self, rng: random.Random) -> list[dict]:
        events = []
        if rng.random() < 0.5:
            events.append({"type": "process", "kind": "new_process", "weight": 5, "name": "chrome.exe", "pid": rng.randrange(1000, 9999)})
        if rng.random() < 0.2:
            events.append({"type": "process", "kind": "mass_writer", "weight": 0, "name": "indexer.exe", "pid": rng.randrange(1000, 9999)})
        return events

    def _attack_system_events(self, rng: random.Random) -> list[dict]:
        events = []
        stealth = self.attack_style in ("stealth", "wiper")
        if not stealth and rng.random() < 0.8:
            events.append({"type": "process", "kind": "shadowcopy", "weight": 70, "name": "vssadmin.exe", "pid": rng.randrange(1000, 9999), "cmdline": "vssadmin delete shadows /all /quiet"})
        if not stealth and rng.random() < 0.7:
            events.append({"type": "process", "kind": "suspicious_binary", "weight": 45, "name": "vssadmin.exe", "pid": rng.randrange(1000, 9999)})
        if rng.random() < 0.6:
            events.append({"type": "process", "kind": "mass_writer", "weight": 40, "name": "encryptor.exe", "pid": rng.randrange(1000, 9999)})
        if rng.random() < 0.5:
            events.append({"type": "resource", "kind": "disk_write", "weight": 35, "value": rng.uniform(400, 1200)})
        if rng.random() < 0.4:
            events.append({"type": "resource", "kind": "cpu_spike", "weight": 15, "value": rng.uniform(85, 100)})
        return events


def build_session(kind: str, root: str, rng: random.Random, n_files: int = 40,
                  n_windows: int = 8, noise: float = 0.0, attack_style: str = "classic") -> dict:
    sandbox = Sandbox(root, n_files=n_files, rng=rng, noise=noise, attack_style=attack_style)
    if kind == "ransomware":
        attack_start = rng.randrange(2, 4)
    else:
        attack_start = None
    return {
        "sandbox": sandbox,
        "kind": kind,
        "attack_start": attack_start,
        "n_windows": n_windows,
        "noise": noise,
        "attack_style": attack_style,
        "rng": rng,
        "root": root,
    }


def build_timeline(n_buckets: int, bucket_size: int, seed: int, root: str,
                   schedule: list[dict], n_files: int = 35, n_windows: int = 7) -> list[dict]:
    """Time-ordered corpus with an *evolving* distribution.

    Each bucket mixes attack styles and benign noise according to the schedule.
    Later buckets contain styles/behaviours that never appear in earlier ones —
    so a model trained on early buckets faces genuinely unseen future data.
    """
    master = random.Random(seed)
    buckets = []
    idx = 0
    for b in range(n_buckets):
        spec = schedule[b] if b < len(schedule) else schedule[-1]
        styles = spec["styles"]
        noise = spec.get("noise", 0.2)
        box = []
        for _ in range(bucket_size):
            rr = random.Random(master.randrange(1 << 30))
            kind = "ransomware" if rr.random() < 0.5 else "benign"
            style = rr.choice(styles)
            root_i = os.path.join(root, f"t{b}_{idx}")
            box.append(build_session(kind, root_i, random.Random(master.randrange(1 << 30)),
                                     n_files=n_files, n_windows=n_windows, noise=noise,
                                     attack_style=style))
            idx += 1
        buckets.append({"bucket": b, "sessions": box})
    return buckets
