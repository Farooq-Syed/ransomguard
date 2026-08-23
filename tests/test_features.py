import os
import random
import tempfile
from pathlib import Path

from ransomguard.config import Config, DEFAULT_CONFIG, deep_merge
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager
from ransomguard_ml.features import FEATURE_NAMES, extract_features
from ransomguard_ml.train import build_dataset
from tools.simulate import build_session


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


def test_extract_session_uses_own_sandbox_root():
    """Regression: each session's features must come from ITS OWN directory.

    A previous bug built one config from sessions[0].root and reused it for
    every session, so FileSystemMonitor/HoneypotManager watched session 0's dir
    and a later ransomware session produced benign-looking filesystem features.
    A non-first ransomware session must still surface attack signals.
    """
    with tempfile.TemporaryDirectory() as tmp:
        benign = build_session("benign", os.path.join(tmp, "b"), random.Random(1),
                               n_files=10, n_windows=5, noise=0.0)
        # benign is deliberately FIRST so a shared config from sessions[0].root
        # would pollute the ransomware session's filesystem features.
        ransom = build_session("ransomware", os.path.join(tmp, "r"), random.Random(2),
                               n_files=10, n_windows=7, noise=0.0, attack_style="classic")

        X, y = build_dataset([benign, ransom])
        X_attack = X[y == 1]
        X_benign = X[y == 0]
        assert X_attack.shape[0] > 0
        i_notes = FEATURE_NAMES.index("n_notes")
        i_honey = FEATURE_NAMES.index("n_honeypot_hits")
        i_ext = FEATURE_NAMES.index("n_appended_ext")
        assert (X_attack[:, i_notes] > 0).any(), "no ransom notes detected in its own sandbox"
        assert (X_attack[:, i_honey] > 0).any(), "no canary tampering detected in its own sandbox"
        assert (X_attack[:, i_ext] > 0).any(), "no extension rewrites detected in its own sandbox"
        assert (X_benign[:, i_notes] == 0).all(), "benign windows should drop no notes"
