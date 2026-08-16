"""Configuration loading with sensible, documented defaults."""
from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

HOME = Path.home()
USERPROFILE = str(HOME).replace("\\", "/")

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    "Temp",
    "$Recycle.Bin",
    "System Volume Information",
    "WinSxS",
    "Package Cache",
    "Microsoft",
    "Google",
    "Mozilla",
    "npm-cache",
    ".cache",
    "logs",
    "LogFiles",
    "Installer",
    "cache",
}

DEFAULT_CONFIG = {
    "scan_interval_seconds": 3,
    "max_files_per_scan": 150000,
    "entropy_threshold": 7.4,
    "entropy_sample_bytes": 8192,
    "entropy_chunks": 6,
    "mod_rate_window_seconds": 60,
    "mod_rate_warn": 100,
    "mod_rate_critical": 600,
    "aged_days": 30,
    "aged_score": 25,
    "honeypot_prefix": "~canary_",
    "honeypot_bait": False,
    "honeypot_dirs": [
        {"path": f"{USERPROFILE}/Documents", "count": 3},
        {"path": f"{USERPROFILE}/Desktop", "count": 2},
    ],
    "hash_tracked": True,
    "hash_track_max_files": 2000,
    "content_hash_bytes": 16384,
    "allowed_writers": [
        "WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "onedrive.exe",
        "SearchIndexer.exe", "SearchProtocolHost.exe", "chrome.exe", "msedge.exe",
        "firefox.exe", "code.exe", "notepad++.exe", "git.exe", "node.exe", "npm",
        "svchost.exe", "system",
    ],
    "event_driven": True,
    "watch_mapped_drives": False,
    "responder": {
        "dry_run": True,
        "kill_suspicious": True,
        "disable_shares": False,
    },
    "cef_log_file": "",
    "drift_warn_z": 3.0,
    "ignore_dirs": sorted(DEFAULT_IGNORE_DIRS),
    "watch_dirs": [
        {"path": f"{USERPROFILE}/Documents", "priority": 70, "recursive": True},
        {"path": f"{USERPROFILE}/Desktop", "priority": 70, "recursive": True},
        {"path": f"{USERPROFILE}/Downloads", "priority": 40, "recursive": True},
        {"path": f"{USERPROFILE}/Pictures", "priority": 55, "recursive": True},
        {"path": f"{USERPROFILE}/Videos", "priority": 55, "recursive": True},
        {"path": f"{USERPROFILE}/.ssh", "priority": 95, "recursive": True},
        {"path": f"{USERPROFILE}/.gnupg", "priority": 95, "recursive": True},
        {"path": f"{USERPROFILE}/.aws", "priority": 95, "recursive": True},
        {"path": f"{USERPROFILE}/.config", "priority": 60, "recursive": True},
        {"path": "C:/", "priority": 30, "recursive": False},
    ],
    "watch_files": [
        {"path": "C:/Windows/System32/drivers/etc/hosts", "priority": 90},
        {"path": "C:/Windows/System32/config/SAM", "priority": 95},
        {"path": "C:/Windows/System32/config/SYSTEM", "priority": 95},
        {"path": "C:/Windows/System32/config/SECURITY", "priority": 95},
        {"path": "C:/Windows/System32/config/SOFTWARE", "priority": 90},
        {"path": "C:/Windows/System32/config/DEFAULT", "priority": 80},
        {"path": "C:/Boot/BCD", "priority": 90},
    ],
    "suspicious_process_names": [
        "vssadmin", "wmic", "bcdedit", "wbadmin", "cipher", "srm",
        "openssl", "gpg", "aescrypt", "privatetool", "taskkill",
    ],
    "shadowcopy_cmd_patterns": [
        "shadowcopy", "shadowcopies", "delete shadows", "shadow delete",
        "vss delete", "vssadmin delete", "bcdedit /set {default} recoveryenabled no",
    ],
    "ransom_note_patterns": [
        r"(?i)readme.*\.(txt|html?)$",
        r"(?i)(how_?to|restore|recover|decrypt|unlock|help).*(read|restore|decrypt|unlock)",
        r"(?i)^!?_?(read|how).*\.(txt|html?)$",
        r"(?i).*_(lock|encrypt|locked|encrypted|crypt|wannacry|ryuk|conti|lockbit)\.(txt|html?)$",
        r"(?i)ryuk.*\.txt$",
    ],
    "appended_extensions": [
        ".lockbit", ".wannacry", ".ryuk", ".conti", ".crypt", ".encrypted",
        ".locked", ".enc", ".aes256", ".clop", ".basta", ".avos", ".cuba",
        ".medusa", ".seth", ".powerranges", ".lock", ".lock64", ".vvv", ".bozok",
    ],
    "resource": {
        "cpu_spike_percent": 80,
        "cpu_sustained_seconds": 10,
        "mem_threshold_percent": 90,
        "disk_write_mbps_threshold": 300,
        "io_window_seconds": 10,
    },
    "webhook_url": "",
    "log_file": "ransomguard.log",
    "quarantine_dir": f"{USERPROFILE}/ransomguard_quarantine",
    "auto_freeze": False,
}


class Config:
    def __init__(self, data: dict):
        self._d = data
        self.scan_interval = float(data["scan_interval_seconds"])
        self.max_files = int(data["max_files_per_scan"])
        self.entropy_threshold = float(data["entropy_threshold"])
        self.entropy_sample = int(data["entropy_sample_bytes"])
        self.entropy_chunks = int(data.get("entropy_chunks", 6))
        self.rate_window = int(data["mod_rate_window_seconds"])
        self.rate_warn = int(data["mod_rate_warn"])
        self.rate_critical = int(data["mod_rate_critical"])
        self.aged_days = int(data["aged_days"])
        self.aged_score = int(data["aged_score"])
        self.honeypot_prefix = data["honeypot_prefix"]
        self.honeypot_bait = bool(data.get("honeypot_bait", False))
        self.hash_tracked = bool(data.get("hash_tracked", True))
        self.hash_track_max_files = int(data.get("hash_track_max_files", 2000))
        self.content_hash_bytes = int(data.get("content_hash_bytes", 16384))
        self.allowed_writers = {str(w).lower() for w in data.get("allowed_writers", [])}
        self.event_driven = bool(data.get("event_driven", True))
        self.watch_mapped_drives = bool(data.get("watch_mapped_drives", False))
        self.responder = data.get("responder", {})
        self.cef_log_file = data.get("cef_log_file", "")
        self.drift_warn_z = float(data.get("drift_warn_z", 3.0))
        self.ignore_dirs = set(data.get("ignore_dirs", []))
        self.honeypot_dirs = data.get("honeypot_dirs", [])
        self.watch_dirs = data.get("watch_dirs", [])
        self.watch_files = data.get("watch_files", [])
        self.suspicious_names = set(data.get("suspicious_process_names", []))
        self.shadowcopy_patterns = data.get("shadowcopy_cmd_patterns", [])
        self.note_patterns = data.get("ransom_note_patterns", [])
        self.appended_extensions = data.get("appended_extensions", [])
        self.resource = data.get("resource", {})
        self.webhook_url = data.get("webhook_url", "")
        self.log_file = data.get("log_file", "ransomguard.log")
        q = data.get("quarantine_dir", "") or ""
        self.quarantine_dir = Path(q).expanduser() if q else None
        self.auto_freeze = bool(data.get("auto_freeze", False))

    def reload_from(self, path: str | Path) -> list[str]:
        """Reload in place (used by config hot-reload). Returns validation issues."""
        new_cfg = load_config(path)
        for k, v in new_cfg._d.items():
            self._d[k] = v
        self.__init__(self._d)
        return validate(self._d)

    def dir_priority(self, path: str) -> int:
        for d in self.watch_dirs:
            if os.path.normcase(os.path.normpath(path)) == os.path.normcase(
                os.path.normpath(os.path.expandvars(os.path.expanduser(d["path"])))
            ):
                return int(d.get("priority", 50))
        return 50

    def file_priority(self, path: str) -> int:
        for f in self.watch_files:
            fp = os.path.normcase(os.path.normpath(os.path.expandvars(os.path.expanduser(f["path"]))))
            if os.path.normcase(os.path.normpath(path)) == fp:
                return int(f.get("priority", 70))
        return 0

    def all_watch_roots(self):
        for d in self.watch_dirs:
            yield os.path.expandvars(os.path.expanduser(d["path"]))
        for f in self.watch_files:
            yield os.path.expandvars(os.path.expanduser(f["path"]))


def deep_merge(base: dict, override: dict) -> dict:
    out = deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path) if path else Path(__file__).resolve().parent.parent / "config.json"
    data = deepcopy(DEFAULT_CONFIG)
    if path.exists():
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        data = deep_merge(data, user)
    return Config(data)


def validate(data: dict) -> list[str]:
    """Return a list of configuration issues (warnings/errors) as strings."""
    issues = []
    types = {
        "scan_interval_seconds": (int, float),
        "entropy_threshold": (int, float),
        "mod_rate_warn": int,
        "mod_rate_critical": int,
        "aged_days": int,
    }
    for key, expected in types.items():
        if key in data and not isinstance(data[key], expected):
            issues.append(f"config key '{key}' should be {expected.__name__}, got {type(data[key]).__name__}")
    if data.get("scan_interval_seconds", 3) <= 0:
        issues.append("scan_interval_seconds must be > 0")
    if data.get("entropy_threshold", 7.4) < 5 or data.get("entropy_threshold", 7.4) > 8:
        issues.append("entropy_threshold should be between 5 and 8 (bits/byte)")
    if data.get("mod_rate_critical", 600) <= data.get("mod_rate_warn", 100):
        issues.append("mod_rate_critical should be greater than mod_rate_warn")
    if data.get("hash_track_max_files", 2000) < 1:
        issues.append("hash_track_max_files must be >= 1")
    for d in data.get("watch_dirs", []):
        if "path" not in d or "priority" not in d:
            issues.append(f"watch_dirs entry missing path/priority: {d}")
    return issues


def write_default_config(path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(DEFAULT_CONFIG, fh, indent=2)
