from typing import Dict

from .utils.constants import AuthClientType
from .utils.utils import debug
from .utils.crypto import hash_string, safe_str_cmp
from .database import get_identity
from .exceptions import ClientAuthenticationError


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
