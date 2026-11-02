"""Encryption of personal data at rest (email addresses).

Values are encrypted with Fernet (AES-128-CBC plus an HMAC-SHA256 integrity check) from the
cryptography library. Fernet encryption is randomised, so the same address encrypts to a
different value each time and an encrypted column cannot be searched. Each email therefore
also gets a blind index: an HMAC-SHA256 of the normalised address under a separate key, used
for lookups (admin login) and for uniqueness.
"""

import hashlib
import hmac
from functools import lru_cache

from cryptography.fernet import Fernet

from phishguard.core.config import get_settings


class EncryptionKeyMissingError(RuntimeError):
    """Raised when an encryption key is needed but not configured."""


@lru_cache
def _fernet() -> Fernet:
    key = get_settings().encryption_key
    if key is None:
        raise EncryptionKeyMissingError("PHISHGUARD_ENCRYPTION_KEY is not set")
    return Fernet(key.get_secret_value().encode("ascii"))


@lru_cache
def _hash_key() -> bytes:
    key = get_settings().email_hash_key
    if key is None:
        raise EncryptionKeyMissingError("PHISHGUARD_EMAIL_HASH_KEY is not set")
    return key.get_secret_value().encode("utf-8")


def clear_key_cache() -> None:
    """Forget cached keys (used by tests and after a key change)."""
    _fernet.cache_clear()
    _hash_key.cache_clear()


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode("ascii")).decode("utf-8")


def normalise_email(email: str) -> str:
    return email.strip().lower()


def email_blind_index(email: str) -> str:
    digest = hmac.new(_hash_key(), normalise_email(email).encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()
