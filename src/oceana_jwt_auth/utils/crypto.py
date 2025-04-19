import os
import base64
import hashlib
import hmac


def generate_key() -> bytes:
    """
    Generate key in bytes
    """
    return base64.urlsafe_b64encode(os.urandom(32))


def generate_salt() -> str:
    """
    Generate salt key url safe
    """
    return generate_key().decode("utf-8")


def hash_string(source_str: str, salt: str) -> str:
    """
    Create a hash using SHA-256 algorithm
    """

    # Create a hash object using SHA-256 algorithm
    hash_object = hashlib.sha256()

    # Update the hash object with a message
    hash_object.update(str(salt).encode("utf-8") + str(source_str).encode("utf-8"))

    # Get the hexadecimal digest of the hash
    hex_dig = hash_object.hexdigest()

    return hex_dig


def safe_str_cmp(a: str, b: str) -> bool:
    """
    This function compares strings in constant time.

    Returns `True` if the two strings are equal, or `False` if they are not.
    """

    if isinstance(a, str):
        a = a.encode("utf-8")  # type: ignore

    if isinstance(b, str):
        b = b.encode("utf-8")  # type: ignore

    return hmac.compare_digest(a, b)
