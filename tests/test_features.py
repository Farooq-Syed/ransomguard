import os
import tempfile
from pathlib import Path

from ransomguard.config import Config, DEFAULT_CONFIG, deep_merge
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager
from ransomguard_ml.features import FEATURE_NAMES, extract_features


def test_features_cover_all_names():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(deep_merge(DEFAULT_CONFIG, {
            "watch_dirs": [{"path": tmp, "priority": 70, "recursive": True}],
            "watch_files": [], "honeypot_dirs": [], "quarantine_dir": "",
        }))
        hp = HoneypotManager(cfg, Path(os.path.join(tmp, "h.json")))
        fs = FileSystemMonitor(cfg, None, hp)
        fs.classify_batch()
        batch = fs.classify_batch()
        feats = extract_features(batch, [], cfg, fs)
        assert all(name in feats for name in FEATURE_NAMES)
        assert len(feats) == len(FEATURE_NAMES)


def test_features_reflect_attack_signals():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "watch")
        os.makedirs(root)
        cfg = Config(deep_merge(DEFAULT_CONFIG, {
            "watch_dirs": [{"path": root, "priority": 70, "recursive": False}],
            "watch_files": [], "honeypot_dirs": [], "quarantine_dir": "",
        }))
        hp = HoneypotManager(cfg, Path(os.path.join(tmp, "h.json")))
        fs = FileSystemMonitor(cfg, None, hp)
        p = os.path.join(root, "docs.docx")
        open(p, "wb").write(b"benign")
        fs.classify_batch()
        open(p, "wb").write(os.urandom(8192))
        batch = fs.classify_batch()
        feats = extract_features(batch, [], cfg, fs)
        assert feats["n_modified"] == 1
        assert feats["n_high_entropy_mod"] == 1
        assert feats["max_entropy_mod"] > 7.4
