"""
auth_guard module

This module provides utilities for handling JWT authentication and authorization
in a Flask application. It includes functions for extracting and verifying JWT tokens,
as well as decorators for protecting routes.
"""

import base64
import json
from typing import List, Union
from typing import Tuple
from functools import wraps
from http import HTTPStatus

from flask import request, g, current_app, Response

from .utils.utils import error, debug, warning
from .utils.constants import AuthAPIRoles, ENDPOINT_SECURITY_LABEL

from .internals import get_jwt_extension
from .api.common import response_api_error
from .exceptions import HttpResponseError, ClientAuthenticationError, \
    ClientBadRequestException, ClientIssuerException

from .config import config
from .config import endpoint_options


def get_token_from_header(allow_missing: bool = False) -> Union[str, None]:
    """
    Extracts the JWT token from the Authorization header in the request.

    :param bool allow_missing:
        If True, the function will not raise an exception if the Authorization header is missing.
        Defaults to False.

    :return:
        The JWT token as a string if present, otherwise None if allow_missing is True.

    :raises:
        :class:`ClientBadRequestException` if the Authorization header is missing and allow_missing is False.
    """

    token = request.headers.get("Authorization")
    if not token:
        if not allow_missing:
            raise ClientBadRequestException("Authorization header missing")
    else:
        token = str(token).strip()
        if not token.startswith("Basic"):
            # Split token and authentication method
            token_split = token.split(" ")
            auth_method = None
            if len(token_split) > 1:
                auth_method = token_split[0]
                token = token_split[1]
            else:
                # Clean Bearer or Basic label if the user doesn't include the space character
                token = token.replace("Bearer", "").replace("Basic", "")

            if not allow_missing and len(token) == 0:
                raise ClientBadRequestException("Bearer access token missing")

            if auth_method != "Bearer":
                # Other authentication method
                if not allow_missing:
                    raise ClientBadRequestException("Authorization header must follow pattern \"Bearer <token_value>\"")
        else:
            raise ClientBadRequestException("Basic authorization is not allowed in JWT")
        # Set token to None if it is empty string
        token = token if len(token) > 0 else None
    return token


def check_token_format(token: Union[str, None]) -> None:
    """
    Extracts the key id from the token header
    """
    try:
        header = token.split(".")[0]
        # Correct the padding
        header += "=" * (4 - len(header) % 4)
        json.loads(base64.b64decode(header).decode("utf-8"))
    except Exception as e:
        raise ClientBadRequestException("Invalid token format") from e


def verify_jwt(optional: bool = False) -> Tuple[dict, dict]:
    """
    Verify that a valid JWT is present in the request, unless ``optional=True`` in
    which case no JWT is also considered valid.

    :param bool optional:
        If ``True``, do not raise an error if no JWT is present in the request.
        Defaults to ``False``.

    :return:
        A tuple containing the jwt_header and the jwt_data if a valid JWT is
        present in the request. If ``optional=True`` and no JWT is in the request,
        empty dictionaries will be returned instead. Raise an exception if an invalid JWT
        is in the request.

    :raises:
        :class:`ClientAuthenticationError` if the token is invalid or expired.
        :class:`ClientIssuerException` if the token issuer is invalid.
    """

    jwt_data = g._jwt_oceana_jwt_data if hasattr(g, "_jwt_oceana_jwt_data") else {}
    jwt_header = g._jwt_oceana_jwt_header if hasattr(g, "_jwt_oceana_jwt_header") else {}

    raised_exception = None
    try:
        # Get token from header
        token = get_token_from_header(allow_missing=False)
        check_token_format(token=token)

        jwt_extension = get_jwt_extension()
        jwt_data, jwt_header = jwt_extension._decode_jwt_from_config(token=token)
        # Save these at the very end so that they are only saved in the request
        # context if the token is valid and all callbacks succeed.
        g._jwt_oceana_jwt_data = jwt_data
        g._jwt_oceana_jwt_header = jwt_header

    except Exception as e:
        raised_exception = e

    if not optional and raised_exception:
        raise raised_exception
    # Return jwt data and header information
    return jwt_data, jwt_header


def decode_unverified_jwt_request() -> Tuple[dict, dict]:
    """
    Decodes the given JWT token without verifying its signature.

    :return:
        A tuple containing two dictionaries:
        - The decoded payload of the JWT token.
        - The unverified header of the JWT token.

    :raises:
        :class:`ClientBadRequestException` if the token is invalid or cannot be decoded.
    """
    jwt_data = {}
    unverified_header = {}

    # Get token from header and check
    token = get_token_from_header(allow_missing=True)
    if token:
        try:
            check_token_format(token=token)
            # Decode jwt from request
            jwt_extension = get_jwt_extension()
            jwt_data, unverified_header = jwt_extension._decode_jwt_unverified_from_config(token=token)
        except Exception:
            pass

    # Save jwt in context for public endpoints
    g._jwt_oceana_jwt_data = jwt_data
    g._jwt_oceana_jwt_header = unverified_header

    return jwt_data, unverified_header


def handle_secured_route(endpoint_id, admin, optional, allowed: List[str]) -> bool:
    """
    Handles the security for a route by verifying the JWT token and checking the user's roles.

    :param endpoint_id:
        The identifier of the endpoint being accessed.

    :param bool admin:
        If True, only users with the admin role are allowed to access the endpoint.

    :param bool optional:
        If True, the presence of a JWT token in the request is optional.

    :param List[str] allowed:
        A list of roles that are allowed to access the endpoint.

    :return:
        True if the user is allowed to access the endpoint, otherwise raises an exception.

    :raises:
        :class:`ClientAuthenticationError` if the user is not allowed to access the endpoint.
    """

    # Verify jwt, if not optional then raises verification exceptions issuer, subject and
    # audience (iss, sub and aud), other custom validations must be set if desired
    jwt_data, jwt_header = verify_jwt(optional=optional)

    # Get roles from jwt
    roles: List[str] = jwt_data.get("roles") or []

    allow = False
    if admin:
        if AuthAPIRoles.ADMIN.value in roles:
            allow = True
        else:
            # Admin can access to the endpoint
            raise ClientAuthenticationError("Only an admin can access to this route")
    else:
        # Verification for token. Will throw HttpResponseError exception if not allowed
        verification_for_token(
            endpoint_id=endpoint_id,
            jwt_header=jwt_header,
            jwt_data=jwt_data,
            optional=optional,
            allowed=allowed,
            roles=roles)
        # If no exception was thrown access is allowed
        allow = True
    return allow


def handle_route_exceptions(route_function, secured, admin, optional, *args, **kwargs):
    """
    Handles route exceptions by applying security checks and executing the decorated view function.

    :param route_function:
        The original route function to be executed.

    :param bool secured:
        If True, the client must be authenticated with a valid JWT token.

    :param bool admin:
        If True, only users with the admin role are allowed to access the endpoint.

    :param bool optional:
        If True, the presence of a JWT token in the request is optional.

    :param args:
        Additional positional arguments to be passed to the route function.

    :param kwargs:
        Additional keyword arguments to be passed to the route function.

    :return:
        The response from the original route function.

    :raises:
        :class:`HttpResponseError` if there is an error in the HTTP response.
        :class:`ClientAuthenticationError` if the client is not authenticated.
        :class:`ClientBadRequestException` if the request is bad.
        :class:`ClientIssuerException` if the token issuer is invalid.
    """
    # Application configuration contains endpoint security
    endpoint_security = current_app.config[ENDPOINT_SECURITY_LABEL]

    # Get endpoint qualified name
    endpoint_id = route_function.__qualname__

    # Decode JWT token if it is present, and stores jwt and header in
    # user's request variables so can be used afterwards
    jwt_data_unverified, _ = decode_unverified_jwt_request()

    # Api security disabled globally (not recommended)
    if not config.api_secured:
        if jwt_data_unverified is not None:
            client_id = jwt_data_unverified.get(config.identity_claim_key, "unknown") \
                if len(jwt_data_unverified) > 0 else "unknown"
            debug(f"Endpoint \"{endpoint_id}\". Authorization for client_id: \"{client_id}\"")
        return current_app.ensure_sync(route_function)(*args, **kwargs)

    # if endpoint not configured then consider it open as default option
    if endpoint_id not in endpoint_security.keys():
        # Proceed to original route function
        if secured:
            warning(f"Endpoint \"{endpoint_id}\" not configured in security repository")

        if admin:
            # Verify jwt against key
            jwt_data, _jwt_header = verify_jwt(optional=False)
            # Get roles
            roles = jwt_data.get("roles") or []
            if AuthAPIRoles.ADMIN.value not in roles:
                # Other roles distinct that admin can't access to the endpoint
                raise ClientAuthenticationError("Only an admin can access to this route")
        return current_app.ensure_sync(route_function)(*args, **kwargs)

    # Check endpoint roles
    allowed = endpoint_security[endpoint_id].get("roles") or []
    debug(f"Endpoint \"{endpoint_id}\" configured in security repository. Allowed roles: {allowed}")

    # Check JWT roles to determine if the client is authorized.
    # It will throw an exception if it is not authorized
    if secured or admin:
        handle_secured_route(endpoint_id, admin, optional, allowed)

    # Proceed to original route function
    return current_app.ensure_sync(route_function)(*args, **kwargs)


def handle_route(route_function, secured, admin, optional, *args, **kwargs) -> Response:
    """
    Route decorator logic to be executed in a decorated view function.
    Captures exceptions and applies security checks, creating a proper response instead of raising exceptions.

    :param route_function:
        The original route function to be executed.

    :param bool secured:
        If True, the client must be authenticated with a valid JWT token.

    :param bool admin:
        If True, only users with the admin role are allowed to access the endpoint.

    :param bool optional:
        If True, the presence of a JWT token in the request is optional.

    :param args:
        Additional positional arguments to be passed to the route function.

    :param kwargs:
        Additional keyword arguments to be passed to the route function.

    :return:
        The response from the original route function or an error response if an exception occurs.
    """

    # Get endpoint qualified name
    endpoint_id = route_function.__qualname__
    try:
        return handle_route_exceptions(
            route_function,
            secured,
            admin,
            optional,
            *args,
            **kwargs
        )
    except HttpResponseError as e:
        error_msg = f"Bearer {e.error_description()}"
        error(f"{error_msg}")
        error(f"Exception: {e}", exc_info=True)
        http_code = e.status_code
        headers = {"WWW-Authenticate": f"{error_msg}"}
        return response_api_error(http_code=http_code, error=error_msg, headers=headers, endpoint=endpoint_id)
    except Exception as e:
        error_msg = f"{e}"
        error(f"{error_msg}")
        error(f"Exception: {e}", exc_info=True)
        http_code = int(HTTPStatus.INTERNAL_SERVER_ERROR.value)
        headers = {"WWW-Authenticate": f"{error_msg}"}
        return response_api_error(http_code=http_code, error=error_msg, headers=headers, endpoint=endpoint_id)
    except BaseException as e:
        error_token = "Token validation failed"
        error_msg = f"Bearer error=\"invalid_token\" error_description=\"{error_token}\""
        # error(f"{error_msg}. Exception: {e}", exc_info=True)
        error(f"{error_msg}")
        error(f"Exception: {e}", exc_info=True)
        http_code = int(HTTPStatus.UNAUTHORIZED.value)
        headers = {"WWW-Authenticate": f"{error_msg}"}
        return response_api_error(http_code=http_code, error=error_msg, headers=headers, endpoint=endpoint_id)


def auth_guard(**kwargs):
    """
    Decorator to protect routes by enforcing authentication and authorization.

    :param bool secured:
        If True, the client must be authenticated with a valid JWT token.
        Defaults to False.

    :param bool admin:
        If True, only users with the admin role are allowed to access the endpoint.
        This overrides the endpoint configuration from the database.
        Defaults to False.

    :param bool optional:
        If True, the presence of a JWT token in the request is optional.
        Defaults to False.

    :return:
        A decorator function that wraps the original function with authentication and authorization checks.

    :raises:
        :class:`~Exception` if the secret doesn't exist, the access token is missing, or the Authorization header
        doesn't follow the pattern "Bearer <token_value>".
    """
    secured: bool = kwargs.get("secured", False)
    admin: bool = kwargs.get("admin", False)
    optional: bool = kwargs.get("optional", False)

    assert isinstance(secured, bool), "Secured parameter has to be boolean"
    assert isinstance(admin, bool), "Admin parameter has to be boolean"
    assert isinstance(optional, bool), "Optional parameter has to be boolean"

    # Set these properties when admin is set
    if admin:
        secured = True
        optional = False

    def wrapper(route_function):

        @wraps(route_function)
        def decorated_function(*args, **kwargs):
            return handle_route(
                route_function,
                secured,
                admin,
                optional,
                *args,
                **kwargs
            )

        # Store endpoint security options configuration
        endpoint_options[route_function.__qualname__] = {
            "admin": admin,
            "secured": secured,
            "optional": optional
        }
        decorated_function.__name__ = route_function.__name__

        return decorated_function
    return wrapper


def get_jwt() -> dict:
    """
    Return python dictionary which has the payload of the JWT that is accessing the endpoint.
    If no JWT is present due to ``auth_guard()``, an empty dictionary is returned.

    :return:
        The payload of the JWT in the current request
    """
    decoded_jwt = g.get("_jwt_oceana_jwt_data", None)
    if decoded_jwt is None:
        raise RuntimeError("You must call `@auth_guard()` before using this method")
    return decoded_jwt


def get_identity() -> str:
    """
    Return the identity of the JWT that is accessing the endpoint.

    :return:
        The identity of the JWT in the current request
    """
    return get_jwt().get(config.identity_claim_key, None)


def verification_for_token(endpoint_id: str,
                           jwt_header: dict,
                           jwt_data: dict,
                           optional: bool,
                           allowed: List[str],
                           roles: List[str]):
    """
    Verifies the JWT token for the given endpoint by checking the issuer and calling a custom verification callback.

    :param str endpoint_id:
        The identifier of the endpoint being accessed.

    :param dict jwt_header:
        The header of the JWT token.

    :param dict jwt_data:
        The decoded payload of the JWT token.

    :param bool optional:
        If True, the presence of a JWT token in the request is optional.

    :param List[str] allowed:
        A list of roles that are allowed to access the endpoint.

    :param List[str] roles:
        A list of roles extracted from the JWT token.

    :raises:
        :class:`ClientIssuerException` if the token issuer is invalid.
        :class:`HttpResponseError` if the token verification callback fails.
    """
    jwt_extension = get_jwt_extension()

    # Issuer only has to be checked when configured jwt as optional, otherwise
    # it has been verified previously
    if optional:
        issuer = jwt_data.get("iss")
        if issuer is not None and issuer != jwt_extension.config().decode_issuer:
            error(f"Issuer error \"{issuer}\" in optional JWT")
            raise ClientIssuerException("Invalid access token: Invalid issuer")

    # Call to token verification function callback
    # Will throw HttpResponseError exception if not allowed
    jwt_extension._token_verification_callback(
        endpoint_id,
        jwt_header,
        jwt_data,
        optional,
        allowed,
        roles)
