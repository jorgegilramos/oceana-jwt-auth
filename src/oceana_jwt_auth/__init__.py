from .config import BaseConfig, Config, ConfigSqlAlchemy, \
    ConfigPostgres, ConfigSqlite, OCEANA_API_PROVIDER
from .utils import logger, API_AUTH_DESCRIPTION, \
    RestMethod, AuthClientType, AuthAPIRoles, \
    string_base64, base64_string, info, debug, error, warning, critical
from .auth_guard import auth_guard, get_jwt, get_identity, verify_jwt
from .auth import authorizations, security, register_auth_namespace
from .jwt_extension import JWTExtension

from .database.db import db
from .database.auth_repository import get_endpoint_security_dict
from .jwt_handler import create_access_token

from .auth_provider import authenticate
from .api.common import handle_exceptions

__version__ = "0.0.5"

__all__ = [
    "BaseConfig", "Config", "ConfigSqlAlchemy", "ConfigSqlite", "ConfigPostgres",
    "OCEANA_API_PROVIDER",
    "logger",
    "API_AUTH_VERSION", "API_AUTH_DESCRIPTION", "RestMethod", "AuthClientType", "AuthAPIRoles",
    "string_base64", "base64_string", "info", "debug", "error", "warning", "critical",
    "authorizations", "security", "register_auth_namespace",
    "auth_guard", "get_jwt", "get_identity", "verify_jwt",
    "JWTExtension", "db", "get_endpoint_security_dict",
    "set_token_verification_function",
    "create_access_token", "authenticate", "handle_exceptions"
]
