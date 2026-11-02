import pytest

from phishguard.core import crypto
from phishguard.core.config import Settings


def test_encrypt_then_decrypt_returns_the_original(crypto_keys):
    token = crypto.encrypt("alice@example.org")

    assert token != "alice@example.org"
    assert crypto.decrypt(token) == "alice@example.org"


def test_encryption_is_randomised(crypto_keys):
    assert crypto.encrypt("alice@example.org") != crypto.encrypt("alice@example.org")


def test_blind_index_ignores_case_and_spaces(crypto_keys):
    assert crypto.email_blind_index(" Alice@Example.ORG ") == crypto.email_blind_index(
        "alice@example.org"
    )


def test_blind_index_differs_per_email_and_is_sha256_hex(crypto_keys):
    first = crypto.email_blind_index("alice@example.org")

    assert first != crypto.email_blind_index("bob@example.org")
    assert len(first) == 64
    int(first, 16)  # hex


def test_missing_keys_raise_a_clear_error(monkeypatch):
    monkeypatch.setattr(crypto, "get_settings", lambda: Settings(_env_file=None))
    crypto.clear_key_cache()

    with pytest.raises(crypto.EncryptionKeyMissingError, match="PHISHGUARD_ENCRYPTION_KEY"):
        crypto.encrypt("alice@example.org")
    with pytest.raises(crypto.EncryptionKeyMissingError, match="PHISHGUARD_EMAIL_HASH_KEY"):
        crypto.email_blind_index("alice@example.org")
    crypto.clear_key_cache()
