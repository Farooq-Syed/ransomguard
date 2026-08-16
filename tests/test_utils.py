import os
import tempfile

from ransomguard import utils


def test_shannon_entropy_low():
    assert utils.shannon_entropy(b"\x00" * 4096) < 0.1


def test_shannon_entropy_high():
    assert utils.shannon_entropy(os.urandom(8192)) > 7.9


def test_sample_entropy_strided_catches_partial_random():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "f.bin")
        with open(p, "wb") as fh:
            fh.write(b"plain text " * 500 + os.urandom(4096) + b"plain text " * 500)
        assert utils.sample_entropy(p, chunks=6) > 7.8


def test_magic_detection():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "img.jpg")
        open(p, "wb").write(b"\xff\xd8\xff\xe0\x00\x10JFIF")
        assert utils.detect_magic(p) == "jpeg"


def test_target_extensions():
    assert utils.is_target_ext("docx")
    assert utils.is_target_ext("PDF")
    assert not utils.is_target_ext("exe")
    assert utils.is_high_value_ext("pem")


def test_ransomware_extension():
    assert utils.is_known_ransomware_ext("report.docx.lockbit") == ".lockbit"
    assert utils.is_known_ransomware_ext("file.doc.crypt")
    assert utils.is_known_ransomware_ext("data.enc") == ".enc"


def test_random_append_extension():
    assert utils.is_known_ransomware_ext("accounts.xlsx.b58eeb") == ".b58eeb"
    assert utils.is_known_ransomware_ext("notes.txt.3d828a")


def test_ransom_note_detection():
    patterns = ["(?i)readme.*\\.(txt|html?)$"]
    assert utils.looks_like_ransom_note("README_RESTORE.txt", patterns)
    assert not utils.looks_like_ransom_note("report_final.docx", patterns)


def test_content_hash_changes_on_rewrite():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "f")
        open(p, "wb").write(b"hello world")
        h1 = utils.content_hash(p)
        open(p, "wb").write(b"hello world ")
        h2 = utils.content_hash(p)
        assert h1 != h2
