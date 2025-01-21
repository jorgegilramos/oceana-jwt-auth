import os
import base64
import hashlib
import hmac
from typing import Dict

from .utils.constants import AuthClientType
from .utils.utils import debug
from .database.auth_repository import get_identity
from .exceptions import ClientAuthenticationError


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


def authenticate(provider, client_id, client_secret) -> Dict:

    identity = get_identity(
        provider=provider,
        client_type=AuthClientType.APPLICATION.value,  # Only applications
        client_id=client_id)

    if identity is not None:
        db_hashed, client_salt, roles = \
            identity[0].client_hash, \
            identity[0].client_salt, \
            identity[0].roles,

        secret_hashed = hash_string(source_str=client_secret, salt=client_salt)

        # Check password against hash
        if not safe_str_cmp(secret_hashed, db_hashed):
            raise ClientAuthenticationError(f"Invalid credentials for client id: \"{client_id}\"")

        # Create list of roles from database
        role_list = [r.strip().lower() for r in str(roles).strip().split(",")]
        debug(f"Client id: {client_id} authenticated OK. Roles: {role_list}")

        # Return identity
        return {
            "client_id": client_id,
            "client_type": AuthClientType.APPLICATION.value,
            "roles": role_list
        }
    else:
        # User not found in the repository, same message to avoid give more information
        raise ClientAuthenticationError(f"Invalid credentials for client id: \"{client_id}\"")
