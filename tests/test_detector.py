import os
import tempfile

from ransomguard.alerter import Alerter
from ransomguard.config import Config, DEFAULT_CONFIG, deep_merge
from ransomguard.detector import Detector
from ransomguard.filesystem_monitor import FileEntry


class _Alerter(Alerter):
    def __init__(self):
        super().__init__(log_file="", webhook_url="")
        self._cooldown = 0.0
        self.history = []

    def emit(self, message, level="INFO", dedup_key=None):
        self.history.append((level, message))


def _config():
    return Config(deep_merge(DEFAULT_CONFIG, {
        "watch_dirs": [{"path": tempfile.gettempdir(), "priority": 70, "recursive": False}],
        "watch_files": [],
        "honeypot_dirs": [],
        "quarantine_dir": "",
        "log_file": "",
        "webhook_url": "",
    }))


def _entry(path):
    st = os.stat(path)
    return FileEntry(path, st.st_size, st.st_mtime_ns, st.st_ctime_ns, None, "docx", "x")


def _write(path, data):
    open(path, "wb").write(data)
    return _entry(path)


def test_benign_activity_stays_warn():
    a = _Alerter()
    d = Detector(_config(), a)
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "f.docx")
        batch = {"modified": [_write(p, b"plain low entropy text")], "new": [], "deleted": [],
                 "renamed": [], "honeypot_hits": [], "note": [], "silent_tamper": []}
        d.handle_scan(batch)
    levels = {lv for lv, _ in a.history}
    assert not levels & {"HIGH", "CRITICAL", "PANDEMIC"}


def test_high_entropy_rewrite_escalates():
    a = _Alerter()
    d = Detector(_config(), a)
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "f.docx")
        batch = {"modified": [_write(p, os.urandom(8192))], "new": [], "deleted": [],
                 "renamed": [], "honeypot_hits": [], "note": [], "silent_tamper": []}
        d.handle_scan(batch)
    assert any(lv in {"HIGH", "CRITICAL", "PANDEMIC"} for lv, _ in a.history)


def test_ransom_note_escalates():
    a = _Alerter()
    d = Detector(_config(), a)
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "README_RESTORE.txt")
        open(p, "wb").write(b"pay up")
        batch = {"modified": [], "new": [_entry(p)], "deleted": [], "renamed": [],
                 "honeypot_hits": [], "note": [p], "silent_tamper": []}
        d.handle_scan(batch)
    assert any(lv in {"HIGH", "CRITICAL", "PANDEMIC"} for lv, _ in a.history)


def test_allowed_writer_suppresses():
    a = _Alerter()
    cfg = _config()
    cfg.allowed_writers = {"winword.exe"}
    d = Detector(cfg, a)
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "f.docx")
        batch = {"modified": [_write(p, os.urandom(8192))], "new": [], "deleted": [],
                 "renamed": [], "honeypot_hits": [], "note": [], "silent_tamper": []}
        writers = [{"type": "attribution", "name": "WINWORD.EXE", "files": 1}]
        d.handle_scan(batch, writers=writers)
    assert not any(lv in {"HIGH", "CRITICAL", "PANDEMIC"} for lv, _ in a.history)


def test_silent_tamper_is_strong():
    a = _Alerter()
    d = Detector(_config(), a)
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "f.docx")
        batch = {"modified": [], "new": [], "deleted": [], "renamed": [],
                 "honeypot_hits": [], "note": [], "silent_tamper": [_write(p, b"new content")]}
        d.handle_scan(batch)
    assert any(lv in {"HIGH", "CRITICAL", "PANDEMIC"} for lv, _ in a.history)
