from typing import TYPE_CHECKING
from typing import List, Any
from flask import current_app

from .utils import EXTENSION_NAME
from .utils.utils import error, debug
from .utils.constants import AuthAPIRoles
from .config import config
from .exceptions import ClientAuthenticationError

# from flask.typing import ResponseReturnValue

if TYPE_CHECKING:  # pragma: no cover
    from .jwt_extension import JWTExtension


def get_jwt_extension() -> "JWTExtension":
    try:
        return current_app.extensions[EXTENSION_NAME]
    except KeyError:
        raise RuntimeError(
            "JWTExtension must be initialized in application before using this method"
        ) from None


def is_authorized(roles, allowed) -> bool:

    # Role all_users gran access to api endpoint
    if AuthAPIRoles.ALLOW_ALL.value in allowed:
        return True

    # Admin can access to everything
    if AuthAPIRoles.ADMIN.value in roles:
        return True
    authorized = False
    for r in roles:
        authorized = r in allowed
        if authorized:
            break
    return authorized


def default_token_verification_callback(endpoint_id: str,
                                        jwt_header: dict,
                                        jwt_data: dict,
                                        optional: bool,
                                        allowed: List[str],
                                        roles: List[str]) -> None:
    """
    Default token verification

    :param str endpoint_id: Argument indicating the endpoint identificator.
    :param dict jwt_header: Dictionary containing the header data of the JWT.
    :param dict jwt_data: Dictionary containing the payload data of the JWT.
    :param bool optional: Boolean ``True`` if JWT is optional in the endpoint
        ``False`` otherwise.
    :param list allowed: List of roles allowed for the endpoint.
    :param list roles: List of roles from the valid JWT

    :return None:
        Throw HttpResponseError exception if not allowed.
    """
    # TODO: verification of the user claims.
    # error_msg = "User claims verification failed"
    # raise UserClaimsVerificationError(error_msg, jwt_header, jwt_data)

    # Authorization gate
    client_id = jwt_data.get(config.identity_claim_key, "unknown") if len(jwt_data) > 0 else "unknown"

    if config.api_secured and not optional:
        assert jwt_header["typ"] == "JWT"
        assert jwt_header["alg"] == config.algorithm

        allow = is_authorized(roles=roles, allowed=allowed)
        if not allow:
            error(f"Endpoint \"{endpoint_id}\". Authorization not granted for client " +
                  f"\"{client_id}\", roles: {roles}, allowed: {allowed}")
            error_msg = "Authorization required"
            raise ClientAuthenticationError(error_msg)

    debug(f"Endpoint \"{endpoint_id}\". Authorization for client_id: \"{client_id}\"")


def default_user_claims_callback(identity: Any) -> dict:
    return {}


def default_encode_key_callback(identity: Any, algorithm) -> str:

    key = config.rsa_private_key if config.requires_cryptography \
        else config.secret_key
    if not key:
        raise RuntimeError("Can't encode without private key")
    return key


def default_decode_key_callback(identity: Any, algorithm) -> str:
    key = config.rsa_public_key if config.requires_cryptography \
        else config.secret_key
    if not key:
        raise RuntimeError("Can't decode without public key")
    return key


def default_token_header_callback(headers: dict) -> dict:
    """
    Use this callback to add labels to JWT tokens header.
    We don't add more labels by default. The two properties of JWT
    header will be set automatically when encoding the payload.
    These properties are the encoding algorithm and the type of token.
    {'alg': 'HS256', 'typ': 'JWT'}

    :return: Dictionary with properties to add
    """
    return {}
