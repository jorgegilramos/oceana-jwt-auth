from enum import Enum

# Flask extension name
EXTENSION_NAME = "oceana-jwt-auth"

# Bind for SQLAlchemy
EXTENSION_BIND = "oceana_jwt_auth"

ENDPOINT_SECURITY_LABEL = "ENDPOINT_SECURITY"

# Authorization api version (in URL)
API_AUTH_DESCRIPTION = "Authentication API"


# Default values for Flask RestX Api
API_AUTH_DEFAULT_TITLE = "Test API"
API_AUTH_DEFAULT_VERSION = "1.0"
API_AUTH_DEFAULT_DESCRIPTION = "Test API"


class RestMethod(Enum):
    GET = "GET"
    POST = "POST"
    DELETE = "DELETE"
    PUT = "PUT"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"


# Security Authorization
class AuthClientType(Enum):
    APPLICATION = "application"
    USER = "user"


class AuthAPIRoles(Enum):
    ALLOW_ALL = "all"
    ADMIN = "admin"
    READER = "reader"
    WRITER = "writer"
