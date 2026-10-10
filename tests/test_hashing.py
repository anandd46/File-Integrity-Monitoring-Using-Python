import hashlib
import os

from fim.hashing import HashError, hash_file


def _expect_error(path, code):
    try:
        hash_file(path)
    except HashError as exc:
        assert exc.code == code, exc.code
        return
    raise AssertionError("HashError not raised")


def test_sha256_matches_known_vector(tmp_path):
    f = tmp_path / "abc.txt"
    f.write_bytes(b"abc")
    assert hash_file(f).sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_empty_file_hash(tmp_path):
    f = tmp_path / "empty"
    f.write_bytes(b"")
    result = hash_file(f)
    assert result.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert result.size == 0


def test_binary_file_hash(tmp_path):
    data = bytes(range(256)) * 50
    f = tmp_path / "blob.bin"
    f.write_bytes(data)
    assert hash_file(f).sha256 == hashlib.sha256(data).hexdigest()


def test_chunked_hashing_matches_single_pass(tmp_path):
    data = os.urandom(100_003)
    f = tmp_path / "big.bin"
    f.write_bytes(data)
    assert hash_file(f, chunk_size=1024).sha256 == hashlib.sha256(data).hexdigest()


def test_hashing_does_not_modify_file(tmp_path):
    f = tmp_path / "keep.txt"
    f.write_text("original")
    before = (f.read_bytes(), f.stat().st_mtime_ns)
    hash_file(f)
    assert (f.read_bytes(), f.stat().st_mtime_ns) == before


def test_missing_file_is_a_safe_error(tmp_path):
    _expect_error(tmp_path / "nope.txt", "MISSING")


def test_directory_is_not_hashable(tmp_path):
    _expect_error(tmp_path, "NOT_REGULAR")


def test_symlink_is_not_followed(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        return  # symlinks unavailable on this platform
    _expect_error(link, "NOT_REGULAR")


def test_file_changing_during_hashing_is_reported(tmp_path):
    f = tmp_path / "moving.txt"
    f.write_text("data")
    real_stat = os.stat
    calls = {"n": 0}

    def fake_stat(path, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:  # the "after hashing" stat: file grew meanwhile
            with open(path, "ab") as handle:
                handle.write(b"tampered")
        return real_stat(path, *args, **kwargs)

    from unittest import mock
    with mock.patch("fim.hashing.os.stat", side_effect=fake_stat):
        _expect_error(f, "UNSTABLE")


def test_permission_denied_is_a_safe_error(tmp_path):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return  # root ignores file permissions; covered by the mocked scanner test
    f = tmp_path / "secret.txt"
    f.write_text("x")
    f.chmod(0)
    try:
        _expect_error(f, "PERMISSION")
    finally:
        f.chmod(0o600)
