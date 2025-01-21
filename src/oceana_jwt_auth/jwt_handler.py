from datetime import datetime, timedelta
import uuid
from typing import Dict, Tuple, Union, Any, Iterable, List, Optional
import copy

import jwt
from jwt import ExpiredSignatureError, InvalidSignatureError, \
    DecodeError, InvalidTokenError

from .internals import get_jwt_extension
from .exceptions import ClientJWTDecodeException, ClientAuthenticationError, \
    ClientBadRequestException, ClientInvalidSignatureException


def encode_jwt(
    algorithm: str,
    audience: Union[str, Iterable[str]],
    claim_overrides: dict,
    expires_delta: timedelta,
    header_overrides: dict,
    identity: Any,
    identity_claim_key: str,
    issuer: str,
    roles: List[str],
    secret: str,
    token_type: str,
    nbf: bool,
    version: str = None,
    payload: Dict = {}

) -> Tuple[str, Dict]:
    """
    Generates a new JWT token with the provided information
    """
    _now = datetime.now()

    token_data = copy.deepcopy(payload)
    token_data.update({
        "iat": _now.timestamp(),
        "jti": str(uuid.uuid4()),
        "type": token_type,
        identity_claim_key: identity,
        "roles": roles,
        # Added "created" in human format date
        "created": _now.strftime("%Y-%m-%d %H:%M:%S")
    })

    if nbf:
        token_data["nbf"] = _now.timestamp()

    if audience:
        token_data["aud"] = audience

    if issuer:
        token_data["iss"] = issuer

    if expires_delta:
        valid_until = _now + expires_delta
        token_data["exp"] = valid_until.timestamp()
        # Added "expires_in" in human format date
        token_data["expires_in"] = valid_until.strftime("%Y-%m-%d %H:%M:%S")

    if version:
        token_data["version"] = version

    if claim_overrides:
        token_data.update(claim_overrides)

    return jwt.encode(
        payload=token_data,
        key=secret,
        algorithm=algorithm,
        headers=header_overrides
    ), token_data


def _decode_jwt(token: str,
                key: str,
                algorithms: List,
                audience: Union[str, Iterable[str]],
                issuer: str,
                options: Dict[str, Any]) -> Tuple[Dict, Dict]:
    """
    Tries to retrieve payload information inside of a existent JWT token (string)
    Will throw an error if the token is invalid (expired or inconsistent)
    """

    try:
        # Call to pyjwt library to verify claims.
        # Always verify ext, iat, and nbf claims, and exp and aud if enabled.
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(
            jwt=token,
            key=key,
            algorithms=algorithms,
            audience=audience,
            issuer=issuer,
            options=options,
        )
    except ExpiredSignatureError as e:
        raise ClientAuthenticationError(f"Invalid access token: {e}")  # 401
    except (InvalidSignatureError, DecodeError) as e:
        raise ClientInvalidSignatureException(f"Invalid access token: {e}")  # 400
    except InvalidTokenError as e:
        raise ClientAuthenticationError(f"Invalid access token: {e}")  # 401
    # Raise rest of exceptions
    return payload, header


def decode_jwt(
    algorithms: List,
    audience: Union[str, Iterable[str]],
    token: str,
    identity_claim_key: str,
    issuer: str,
    key: str,
    version: str,
    verify_aud: bool,
    verify_sub: bool,
    verify_version: bool
) -> Tuple[Dict, Dict]:

    options = {"verify_aud": verify_aud, "verify_sub": verify_sub}

    payload, header = _decode_jwt(token=token,
                                  key=key,
                                  algorithms=algorithms,
                                  audience=audience,
                                  issuer=issuer,
                                  options=options)

    # Make sure that any custom claims we expect in the token are present
    if identity_claim_key not in payload:
        raise ClientJWTDecodeException(f"Invalid access token: Missing claim: {identity_claim_key}")

    if verify_version:
        if "version" not in payload:
            raise ClientJWTDecodeException("Invalid access token: Missing claim: version")

        if payload["version"] != version:
            raise ClientJWTDecodeException("Invalid access token: Token version doesn't match")

    # Set default properties if not present
    if "type" not in payload:
        payload["type"] = "access"

    if "jti" not in payload:
        payload["jti"] = None

    return payload, header


def decode_jwt_unverified(
    algorithms: List,
    token: str,
) -> Tuple[Dict, Dict]:

    try:
        header = jwt.get_unverified_header(token)
        unverified_payload = jwt.decode(
            token,
            algorithms=algorithms,
            # Also doesn't raise expiration signature exception
            options={"verify_signature": False}
        )
    except Exception as e:
        raise ClientBadRequestException(f"Invalid access token: {e}")

    return unverified_payload, header


def create_access_token(
    identity: Any,
    roles: List[str],
    expires_delta: Optional[timedelta] = None,
    additional_claims=None,
    additional_headers=None,
    payload: Dict = {}
) -> Tuple[str, Dict]:

    # Get extension
    jwt_manager = get_jwt_extension()
    return jwt_manager._encode_jwt_from_config(
        identity=identity,
        roles=roles,
        token_type="access",
        claims=additional_claims,
        expires_delta=expires_delta,
        headers=additional_headers,
        version=None,
        payload=payload
    )
