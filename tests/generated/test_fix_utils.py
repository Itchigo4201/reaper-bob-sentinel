"""
Auto-generated regression tests for PATH_TRAVERSAL and WEAK_CRYPTO fixes in utils_safe.py.
Rules: PATH_TRAVERSAL (A01:2021), WEAK_CRYPTO (A02:2021)
"""
import os
import pytest
from pathlib import Path


def _read_file_safe(filename):
    from vulnerable_app.utils_safe import read_file
    return read_file(filename)


def _hash_password_safe(password):
    from vulnerable_app.utils_safe import hash_password
    return hash_password(password)


def _verify_password_safe(password, stored):
    from vulnerable_app.utils_safe import verify_password
    return verify_password(password, stored)


class TestUtilsSafePathTraversal:
    def test_traversal_payload_raises(self):
        """Traversal sequences must be rejected with ValueError."""
        with pytest.raises(ValueError, match="escapes the base directory"):
            _read_file_safe("../../../etc/passwd")

    def test_double_encoded_traversal_raises(self):
        """Traversal via double-dots must be caught regardless of depth."""
        with pytest.raises(ValueError, match="escapes the base directory"):
            _read_file_safe("../../sensitive")

    def test_absolute_path_raises(self):
        """An absolute path that leaves BASE_DIR must also be rejected."""
        with pytest.raises((ValueError, OSError)):
            _read_file_safe("/etc/passwd")

    def test_scanner_reports_no_path_traversal_in_safe(self):
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py")
        findings = [f for f in scan_file(path, "utils_safe.py") if f.rule_id == "PATH_TRAVERSAL"]
        assert findings == [], f"Unexpected findings: {findings}"


class TestUtilsSafeWeakCrypto:
    def test_md5_not_in_source(self):
        """utils_safe.py must not call hashlib.md5."""
        src = (Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py").read_text()
        assert "hashlib.md5" not in src, "hashlib.md5 still present in utils_safe.py"

    def test_scrypt_used_in_source(self):
        """utils_safe.py must use hashlib.scrypt for password hashing."""
        src = (Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py").read_text()
        assert "hashlib.scrypt" in src, "hashlib.scrypt not found in utils_safe.py"

    def test_hash_contains_salt_separator(self):
        """Stored hash must embed the salt: format is <salt_hex>$<key_hex>."""
        stored = _hash_password_safe("password123")
        assert "$" in stored, f"Expected salt$key format, got: {stored!r}"
        salt_hex, key_hex = stored.split("$", 1)
        assert len(salt_hex) == 32, f"Expected 16-byte salt (32 hex chars), got {len(salt_hex)}"
        assert len(key_hex) > 0, "Derived key portion must not be empty"

    def test_each_hash_has_unique_salt(self):
        """Two hashes of the same password must use different salts."""
        h1 = _hash_password_safe("abc")
        h2 = _hash_password_safe("abc")
        salt1 = h1.split("$")[0]
        salt2 = h2.split("$")[0]
        assert salt1 != salt2, "Salt must be randomly generated, not static"

    def test_verify_correct_password_succeeds(self):
        """verify_password() must return True for the correct password."""
        stored = _hash_password_safe("correct_horse_battery")
        assert _verify_password_safe("correct_horse_battery", stored) is True

    def test_verify_wrong_password_fails(self):
        """verify_password() must return False for an incorrect password."""
        stored = _hash_password_safe("correct_horse_battery")
        assert _verify_password_safe("wrong_password", stored) is False

    def test_verify_empty_password_fails(self):
        stored = _hash_password_safe("nonempty")
        assert _verify_password_safe("", stored) is False

    def test_verify_malformed_stored_returns_false(self):
        """verify_password() must not raise on a malformed stored value (missing $)."""
        assert _verify_password_safe("anything", "no-dollar-sign-here") is False

    def test_verify_invalid_hex_returns_false(self):
        """verify_password() must return False when salt or key is invalid hex."""
        assert _verify_password_safe("anything", "nothex$alsonothex") is False

    def test_verify_function_exists(self):
        """utils_safe.py must export verify_password."""
        from vulnerable_app import utils_safe
        assert hasattr(utils_safe, "verify_password"), "verify_password not found in utils_safe"

    def test_scanner_reports_no_weak_crypto_in_safe(self):
        from sentinel.scanner import scan_file
        path = str(Path(__file__).parent.parent.parent / "vulnerable_app" / "utils_safe.py")
        findings = [f for f in scan_file(path, "utils_safe.py") if f.rule_id == "WEAK_CRYPTO"]
        assert findings == [], f"Unexpected findings: {findings}"
