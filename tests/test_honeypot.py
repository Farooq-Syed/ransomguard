import os
import tempfile
import time
from pathlib import Path

from ransomguard.alerter import Alerter
from ransomguard.config import Config, DEFAULT_CONFIG, deep_merge
from ransomguard.filesystem_monitor import FileSystemMonitor
from ransomguard.honeypot import HoneypotManager


def _honeypot_manager(manifest_path, root):
    cfg = Config(deep_merge(DEFAULT_CONFIG, {
        "honeypot_dirs": [{"path": root, "count": 2}],
        "honeypot_prefix": "~canary_",
    }))
    return HoneypotManager(cfg, manifest_path)


def test_honeypot_setup_verify_tamper():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "honey")
        os.makedirs(root)
        manifest = os.path.join(tmp, "h.json")
        hp = _honeypot_manager(Path(manifest), root)
        planted = hp.setup()
        assert len(planted) == 2
        assert hp.is_honeypot(planted[0])
        missing, tampered = hp.verify()
        assert not missing and not tampered
        Path(planted[0]).write_bytes(b"tampered!")
        _, tampered = hp.verify()
        assert planted[0] in tampered
        hp.remove()
        assert not hp.manifest


def test_honeypot_randomized_names():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "honey")
        os.makedirs(root)
        manifest = os.path.join(tmp, "h.json")
        hp = _honeypot_manager(Path(manifest), root)
        planted = hp.setup()
        for p in planted:
            assert "~canary_" not in os.path.basename(p)


def test_fs_monitor_silent_tamper():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "critical")
        os.makedirs(root)
        target = os.path.join(root, "secret.pem")
        open(target, "wb").write(b"content-v1")
        st = os.stat(target)
        cfg = Config(deep_merge(DEFAULT_CONFIG, {
            "watch_dirs": [{"path": root, "priority": 95, "recursive": False}],
            "watch_files": [],
            "honeypot_dirs": [],
            "hash_tracked": True,
            "quarantine_dir": "",
        }))
        hp = HoneypotManager(cfg, Path(os.path.join(tmp, "h.json")))
        fs = FileSystemMonitor(cfg, None, hp)
        fs.classify_batch()  # baseline
        open(target, "wb").write(b"content-v2")  # same size as "content-v1"
        os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns))  # restore timestamps exactly
        batch = fs.classify_batch()
        assert batch["modified"] == []
        assert len(batch["silent_tamper"]) == 1
        assert batch["silent_tamper"][0].path == target
