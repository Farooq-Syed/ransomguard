"""File analysis helpers: Shannon entropy, magic-byte signatures, priority tables."""
from __future__ import annotations

import math
import os
import re

MAGIC_SIGNATURES = [
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip/office"),
    (b"PK\x05\x06", "zip-empty"),
    (b"PK\x07\x08", "zip-spanned"),
    (b"MZ", "pe-executable"),
    (b"\x7fELF", "elf"),
    (b"RIFF", "riff-media"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3"),
    (b"fLaC", "flac"),
    (b"BM", "bmp"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"SQLite format 3", "sqlite"),
    (b"{\\rtf", "rtf"),
    (b"<?xml", "xml"),
]

TARGET_EXTENSIONS = {
    "txt", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "pps", "ppsx",
    "odt", "ods", "odp", "rtf", "csv", "pdf",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "raw", "nef", "cr2", "dng",
    "mp3", "wav", "flac", "aac", "m4a", "mp4", "mkv", "avi", "mov", "wmv", "mpg", "mpeg",
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso",
    "db", "dbf", "mdb", "accdb", "sql", "sqlite", "sqlite3",
    "py", "js", "ts", "java", "c", "cpp", "h", "cs", "go", "php", "rb", "pl", "sh", "ps1", "bat",
    "cfg", "ini", "conf", "yaml", "yml", "json", "env", "key", "pem", "pfx", "p12",
    "bak", "old", "backup", "vmdk", "vdi", "vhdx", "qcow2", "ost", "pst", "eml", "msg",
    "crt", "cer", "der", "jks", "keystore", "wallet", "dat",
}

HIGH_VALUE_EXTENSIONS = {
    "key", "pem", "pfx", "p12", "jks", "keystore", "wallet",
    "pst", "ost", "sql", "sqlite", "sqlite3", "accdb", "db",
    "vmdk", "vdi", "vhdx", "qcow2", "bak", "backup", "old",
    "docx", "xlsx", "pptx", "pdf",
}

KNOWN_RANSOMWARE_EXTENSIONS = {
    ".lockbit", ".wannacry", ".ryuk", ".conti", ".crypt", ".encrypted",
    ".locked", ".enc", ".aes256", ".clop", ".basta", ".avos", ".cuba",
    ".medusa", ".seth", ".powerranges", ".lock", ".lock64", ".vvv", ".bozok",
    ".avos2", ".avoslinux", ".mkp", ".wasted", ".onyx", ".play", ".stop",
}

RANDOM_APPEND_RE = re.compile(r"^([0-9a-f]{6,16}|[A-Z0-9]{6,12})$", re.IGNORECASE)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    log2 = math.log2
    for count in freq:
        if count:
            p = count / length
            entropy -= p * log2(p)
    return entropy


def sample_entropy(path: str, max_bytes: int = 8192, chunks: int = 3) -> float:
    try:
        size = os.path.getsize(path)
        if size <= 0:
            return 0.0
        if size <= max_bytes:
            with open(path, "rb") as fh:
                return shannon_entropy(fh.read())
        chunk = max(256, max_bytes // chunks)
        offset = max(0, (size - chunk) // 2)
        tail = max(0, size - chunk)
        samples = []
        with open(path, "rb") as fh:
            fh.seek(0)
            samples.append(fh.read(chunk))
            fh.seek(offset)
            samples.append(fh.read(chunk))
            fh.seek(tail)
            samples.append(fh.read(chunk))
        return max(shannon_entropy(s) for s in samples)
    except OSError:
        return 0.0


def detect_magic(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return None
    for sig, label in MAGIC_SIGNATURES:
        if head.startswith(sig):
            return label
    if head:
        return None
    return "empty"


def classify_magic_change(old_magic: str | None, new_magic: str | None) -> bool:
    if old_magic in (None, "empty", "random", "unknown") or new_magic in (None, "empty"):
        return False
    if old_magic == "random" or new_magic == "random":
        return old_magic != new_magic
    return old_magic != new_magic


def get_ext(name: str) -> str:
    dot = name.rfind(".")
    if dot <= 0:
        return ""
    ext = name[dot + 1 :].lower()
    return ext if len(ext) <= 12 else ""


def is_target_ext(ext: str) -> bool:
    return ext in TARGET_EXTENSIONS


def is_high_value_ext(ext: str) -> bool:
    return ext in HIGH_VALUE_EXTENSIONS


def is_known_ransomware_ext(full_name: str) -> str | None:
    lower = full_name.lower()
    for ext in KNOWN_RANSOMWARE_EXTENSIONS:
        if lower.endswith(ext):
            return ext
    dot = lower.rfind(".")
    if dot > 0:
        tail = lower[dot + 1 :]
        if RANDOM_APPEND_RE.match(tail) and not is_target_ext(tail):
            return "." + tail
    return None


def looks_like_ransom_note(name: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if re.search(pat, name):
            return True
    return False
