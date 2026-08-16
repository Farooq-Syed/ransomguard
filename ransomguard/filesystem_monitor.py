"""Filesystem monitoring: periodic snapshot + diff with ransomware classification."""
from __future__ import annotations

import os
import time
from collections import defaultdict
from pathlib import Path

from . import utils
from .alerter import Alerter
from .honeypot import HoneypotManager

_IGNORE_PARTS = ["$recycle.bin", "system volume information", "winsxs", "node_modules"]


class FileEntry:
    __slots__ = ("path", "size", "mtime_ns", "ctime_ns", "magic", "ext", "stem")

    def __init__(self, path: str, size: int, mtime_ns: int, ctime_ns: int, magic, ext: str, stem: str):
        self.path = path
        self.size = size
        self.mtime_ns = mtime_ns
        self.ctime_ns = ctime_ns
        self.magic = magic
        self.ext = ext
        self.stem = stem

    def __repr__(self):
        return f"<FileEntry {os.path.basename(self.path)} {self.size}b>"


def _ignored_dir(name: str, full_path: str, ignore_dirs: set[str]) -> bool:
    if name in ignore_dirs:
        return True
    low = full_path.lower()
    for part in _IGNORE_PARTS:
        if part in low:
            return True
    return False


class FileSystemMonitor:
    def __init__(self, config, alerter: Alerter, honeypots: HoneypotManager):
        self.config = config
        self.alerter = alerter
        self.honeypots = honeypots
        self._baseline: dict[str, FileEntry] = {}
        self._stem_map: dict[tuple, list[tuple]] = {}
        self._scan_stats = {"files": 0, "dirs": 0, "limited": False}
        self._ready = False

    def priority_for(self, path: str) -> int:
        pri = self.config.file_priority(path)
        if pri:
            return pri
        norm = os.path.normcase(path)
        for d in self.config.watch_dirs:
            root = os.path.normcase(os.path.expandvars(os.path.expanduser(d["path"])))
            if norm.startswith(root + os.sep) or norm.startswith(root + "/"):
                return int(d.get("priority", 50))
        return 30

    def _dirs_to_scan(self) -> list[tuple[str, int, bool]]:
        result = []
        for d in self.config.watch_dirs:
            root = os.path.expandvars(os.path.expanduser(d["path"]))
            result.append((root, int(d.get("priority", 50)), bool(d.get("recursive", True))))
        return result

    def _scan_snapshot(self) -> dict[str, FileEntry]:
        out: dict[str, FileEntry] = {}
        count = 0
        for root, priority, recursive in self._dirs_to_scan():
            if not os.path.isdir(root):
                continue
            if recursive:
                count = self._walk(root, out, count)
            else:
                count = self._scan_flat(root, out, count)
        for spec in self.config.watch_files:
            p = os.path.expandvars(os.path.expanduser(spec["path"]))
            try:
                st = os.stat(p)
            except OSError:
                continue
            if p not in out:
                out[p] = self._make_entry(p, st)
                count += 1
        self._scan_stats["files"] = count
        self._scan_stats["limited"] = count >= self.config.max_files
        return out

    def _walk(self, root: str, out: dict, count: int) -> int:
        ignore = self.config.ignore_dirs
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if not _ignored_dir(d, os.path.join(dirpath, d), ignore)
            ]
            for name in filenames:
                p = os.path.join(dirpath, name)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if not os.path.isfile(p):
                    continue
                out[p] = self._make_entry(p, st)
                count += 1
                if count >= self.config.max_files:
                    return count
        return count

    def _scan_flat(self, root: str, out: dict, count: int) -> int:
        try:
            with os.scandir(root) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        continue
                    try:
                        st = entry.stat()
                    except OSError:
                        continue
                    out[entry.path] = self._make_entry(entry.path, st)
                    count += 1
                    if count >= self.config.max_files:
                        break
        except OSError:
            pass
        return count

    @staticmethod
    def _make_entry(path: str, st: os.stat_result) -> FileEntry:
        base = os.path.basename(path)
        dot = base.rfind(".")
        ext = base[dot + 1 :].lower() if 0 < dot < len(base) - 1 else ""
        stem = base[:dot] if dot > 0 else base
        return FileEntry(
            path=path,
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
            ctime_ns=st.st_ctime_ns,
            magic=utils.detect_magic(path),
            ext=ext,
            stem=stem,
        )

    @staticmethod
    def _build_stem_map(snapshot: dict[str, FileEntry]) -> dict:
        m = defaultdict(list)
        for e in snapshot.values():
            key = (os.path.dirname(e.path).lower(), e.stem.lower())
            m[key].append((e.ext, e.path))
        return dict(m)

    def _age_days(self, entry: FileEntry) -> float:
        return (time.time() - entry.mtime_ns / 1e9) / 86400.0

    def classify_batch(self) -> dict:
        snapshot = self._scan_snapshot()
        if not self._ready:
            self._baseline = snapshot
            self._stem_map = self._build_stem_map(snapshot)
            self._ready = True
            return {"status": "baseline", "files": len(snapshot), **self._scan_stats}

        batch = {"new": [], "modified": [], "deleted": [], "renamed": [], "honeypot_hits": [], "note": []}
        old = self._baseline
        hp = self.honeypots.planted_paths()

        for path, entry in snapshot.items():
            prev = old.get(path)
            if prev is None:
                batch["new"].append(entry)
                if self.honeypots.is_honeypot(path):
                    batch["honeypot_hits"].append(entry)
            elif prev.size != entry.size or prev.mtime_ns != entry.mtime_ns:
                batch["modified"].append(entry)
                if self.honeypots.is_honeypot(path):
                    batch["honeypot_hits"].append(entry)

        for path, entry in old.items():
            if path not in snapshot:
                batch["deleted"].append(entry)
                if self.honeypots.is_honeypot(path):
                    batch["honeypot_hits"].append(entry)

        new_stem_map = self._build_stem_map(snapshot)
        for key, new_list in new_stem_map.items():
            old_list = self._stem_map.get(key)
            if not old_list:
                continue
            new_exts = {ext for ext, _ in new_list}
            old_exts = {ext for ext, _ in old_list}
            added = new_exts - old_exts
            if added:
                for ext, path in new_list:
                    if ext in added and ext not in (e.lower() for e in old_exts):
                        batch["renamed"].append((path, sorted(added)))

        for entry in batch["new"]:
            base = os.path.basename(entry.path)
            if utils.looks_like_ransom_note(base, self.config.note_patterns):
                batch["note"].append(entry.path)

        self._baseline = snapshot
        self._stem_map = new_stem_map
        return {**batch, "files": len(snapshot), **self._scan_stats}
