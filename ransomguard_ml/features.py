"""Window-level feature extraction shared by training and runtime."""
from __future__ import annotations

import os
import time

from ransomguard import utils

FEATURE_NAMES = [
    "n_new",
    "n_modified",
    "n_deleted",
    "n_renamed",
    "n_notes",
    "n_appended_ext",
    "n_honeypot_hits",
    "n_high_entropy_mod",
    "n_magic_change",
    "n_aged_mod",
    "n_target_mod",
    "n_high_value_mod",
    "n_target_new",
    "n_high_value_new",
    "mean_entropy_mod",
    "max_entropy_mod",
    "mean_entropy_new",
    "max_entropy_new",
    "n_deleted_target",
    "n_crypto_procs",
    "n_suspicious_procs",
    "n_mass_writer_procs",
    "disk_write_mbps",
    "cpu_spike",
    "mem_pressure",
    "n_files",
]


def _entropy(path: str, max_bytes: int = 8192) -> float:
    return utils.sample_entropy(path, max_bytes)


def extract_features(batch: dict, events: list[dict], config, fs) -> dict:
    f = {name: 0.0 for name in FEATURE_NAMES}
    max_bytes = config.entropy_sample
    threshold = config.entropy_threshold

    mod_entropies = []
    new_entropies = []
    for entry in batch.get("modified", []):
        f["n_modified"] += 1
        entropy = _entropy(entry.path, max_bytes)
        mod_entropies.append(entropy)
        if entropy >= threshold:
            f["n_high_entropy_mod"] += 1
        prev = fs._baseline.get(entry.path)
        if prev and utils.classify_magic_change(prev.magic, entry.magic):
            f["n_magic_change"] += 1
        if utils.is_target_ext(entry.ext):
            f["n_target_mod"] += 1
        if utils.is_high_value_ext(entry.ext):
            f["n_high_value_mod"] += 1
        if (time.time() - entry.mtime_ns / 1e9) / 86400.0 > config.aged_days:
            f["n_aged_mod"] += 1

    for entry in batch.get("new", []):
        f["n_new"] += 1
        entropy = _entropy(entry.path, max_bytes)
        new_entropies.append(entropy)
        if utils.is_target_ext(entry.ext):
            f["n_target_new"] += 1
        if utils.is_high_value_ext(entry.ext):
            f["n_high_value_new"] += 1

    f["n_deleted"] += len(batch.get("deleted", []))
    for entry in batch.get("deleted", []):
        if utils.is_target_ext(entry.ext):
            f["n_deleted_target"] += 1

    f["n_renamed"] += len(batch.get("renamed", []))
    f["n_notes"] += len(batch.get("note", []))
    f["n_honeypot_hits"] += len(batch.get("honeypot_hits", []))

    for entry in batch.get("new", []):
        base = os.path.basename(entry.path)
        if utils.is_known_ransomware_ext(base):
            f["n_appended_ext"] += 1

    if mod_entropies:
        f["mean_entropy_mod"] = sum(mod_entropies) / len(mod_entropies)
        f["max_entropy_mod"] = max(mod_entropies)
    if new_entropies:
        f["mean_entropy_new"] = sum(new_entropies) / len(new_entropies)
        f["max_entropy_new"] = max(new_entropies)

    for ev in events:
        kind = ev.get("kind")
        if kind in ("shadowcopy", "suspicious_binary"):
            f["n_crypto_procs"] += 1
        if kind == "suspicious_binary":
            f["n_suspicious_procs"] += 1
        if kind == "mass_writer":
            f["n_mass_writer_procs"] += 1
        if kind == "disk_write":
            f["disk_write_mbps"] = max(f["disk_write_mbps"], float(ev.get("value", 0)))
        if kind == "cpu_spike":
            f["cpu_spike"] = max(f["cpu_spike"], float(ev.get("value", 0)))
        if kind == "memory":
            f["mem_pressure"] = max(f["mem_pressure"], float(ev.get("value", 0)))

    f["n_files"] = batch.get("files", 0)
    return f
