from decouple import config as _config
from flask import current_app
from jwt.algorithms import requires_cryptography, get_default_algorithms
from datetime import timedelta

from typing import Union, Iterable

# Database provider and issuer of JWT tokens
OCEANA_API_PROVIDER = _config("OCEANA_API_PROVIDER", default="OceanaAPI", cast=str)

# Security properties
OCEANA_API_SECURED = _config("OCEANA_API_SECURED", default=True, cast=bool)
# Oceana API secret key
OCEANA_API_SECRET_KEY = _config("OCEANA_API_SECRET_KEY", default="", cast=str)
# Generate a token with valid within 1 hour by now (in minutes)
OCEANA_API_TOKEN_MAX_MINUTES = _config("OCEANA_API_TOKEN_MAX_MINUTES", default=60, cast=int)

# Encode and decode issuer in JWT tokens
OCEANA_API_TOKEN_ENCODE_ISSUER = _config("OCEANA_API_TOKEN_ENCODE_ISSUER", default=OCEANA_API_PROVIDER)
OCEANA_API_TOKEN_DECODE_ISSUER = _config("OCEANA_API_TOKEN_DECODE_ISSUER", default=OCEANA_API_PROVIDER)

# RSA algorithm private and public keys
OCEANA_API_RSA_PRIVATE_KEY = _config("OCEANA_API_RSA_PRIVATE_KEY", default="", cast=str)
OCEANA_API_RSA_PUBLIC_KEY = _config("OCEANA_API_RSA_PUBLIC_KEY", default="", cast=str)

# Logger Configuration
OCEANA_API_LOGGING_LEVEL = _config("OCEANA_API_LOGGING_LEVEL", "INFO")
OCEANA_API_DEBUG = _config("OCEANA_API_DEBUG", False, cast=bool)
OCEANA_API_LOGGING_DIR = _config("OCEANA_API_LOGGING_DIR", "logs")
OCEANA_API_LOGGING_FILE = _config("OCEANA_API_LOGGING_FILE", "oceana-jwt-auth.log")
OCEANA_API_LOGGING_WHEN = _config("OCEANA_API_LOGGING_WHEN", "midnight")
OCEANA_API_LOGGING_INTERVAL = _config("OCEANA_API_LOGGING_INTERVAL", 1)
OCEANA_API_LOGGING_TITLE = _config("OCEANA_API_LOGGING_TITLE", "oceana-jwt-auth")


OCEANA_API_TOKEN_ALGORITHM = _config("OCEANA_API_TOKEN_ALGORITHM", "HS256")
# Refresh token expiration in minutes
OCEANA_API_TOKEN_REFRESH_MAX_MINUTES = _config("OCEANA_API_TOKEN_REFRESH_MAX_MINUTES", default=60, cast=int)

# Authorization api version (in URL)
OCEANA_API_AUTH_VERSION = _config("OCEANA_API_AUTH_VERSION", None)  # "v1"

# Audiences
OCEANA_API_TOKEN_ENCODE_AUDIENCE = _config("OCEANA_API_TOKEN_ENCODE_AUDIENCE", None)
OCEANA_API_TOKEN_DECODE_AUDIENCE = _config("OCEANA_API_TOKEN_DECODE_AUDIENCE", None)


# Token version (internal in JWT)
OCEANA_API_TOKEN_VERSION = "v1"

# Verifications
OCEANA_API_TOKEN_VERIFY_SUB = _config("OCEANA_API_TOKEN_VERIFY_SUB", default=True, cast=bool)
OCEANA_API_TOKEN_VERIFY_VERSION = _config("OCEANA_API_TOKEN_VERIFY_VERSION", default=True, cast=bool)

# Register authorization namespace
OCEANA_API_REGISTER_AUTH = _config("OCEANA_API_REGISTER_AUTH", True, cast=bool)

# Token JWT Algorithms
ALGORITHMS = [a for a in get_default_algorithms().keys() if a != "none"]


# Flask application base config
class BaseConfig:

    @property
    def api_secured(self) -> bool:
        return self._get_bool("SECURED", OCEANA_API_SECURED)

    @property
    def secret_key(self) -> str:
        return current_app.config.get("SECRET_KEY") or OCEANA_API_SECRET_KEY

    # Algorithms:
    # HS256 - HMAC using SHA-256 hash algorithm (default)
    # HS384 - HMAC using SHA-384 hash algorithm
    # HS512 - HMAC using SHA-512 hash algorithm
    # ES256 - ECDSA signature algorithm using SHA-256 hash algorithm
    # ES256K - ECDSA signature algorithm with secp256k1 curve using SHA-256 hash algorithm
    # ES384 - ECDSA signature algorithm using SHA-384 hash algorithm
    # ES512 - ECDSA signature algorithm using SHA-512 hash algorithm
    # RS256 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm
    # RS384 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm
    # RS512 - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm
    # PS256 - RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256
    # PS384 - RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384
    # PS512 - RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512
    # EdDSA - Both Ed25519 signature using SHA-512 and Ed448 signature using SHA-3 are supported.
    #     Ed25519 and Ed448 provide 128-bit and 224-bit security respectively.

    @property
    def algorithm(self) -> str:
        return current_app.config.get("TOKEN_ALGORITHM") or OCEANA_API_TOKEN_ALGORITHM

    # RSA algorithm
    @property
    def requires_cryptography(self) -> bool:
        return self.algorithm in requires_cryptography

    @property
    def rsa_private_key(self) -> str:
        return current_app.config.get("RSA_PRIVATE_KEY") or OCEANA_API_RSA_PRIVATE_KEY

    @property
    def rsa_public_key(self) -> str:
        return current_app.config.get("RSA_PUBLIC_KEY") or OCEANA_API_RSA_PUBLIC_KEY

    @property
    def access_token_delta(self) -> timedelta:
        delta = current_app.config.get("TOKEN_MAX_MINUTES") or OCEANA_API_TOKEN_MAX_MINUTES
        return timedelta(minutes=delta)

    # TODO: Implement refresh tokens
    # @property
    # def refresh_token_delta(self) -> timedelta:
    #     delta = current_app.config.get("TOKEN_REFRESH_MAX_MINUTES") or OCEANA_API_TOKEN_REFRESH_MAX_MINUTES
    #     return timedelta(minutes=delta)

    # @property
    # def api_auth_version(self):
    #     return current_app.config.get("API_AUTH_VERSION") or OCEANA_API_AUTH_VERSION

    @property
    def encode_issuer(self) -> str:
        return current_app.config.get("TOKEN_ENCODE_ISSUER") or OCEANA_API_TOKEN_ENCODE_ISSUER

    @property
    def decode_issuer(self) -> str:
        return current_app.config.get("TOKEN_DECODE_ISSUER") or OCEANA_API_TOKEN_DECODE_ISSUER

    @property
    def encode_audience(self) -> Union[str, Iterable[str]]:
        return current_app.config.get("TOKEN_ENCODE_AUDIENCE") or OCEANA_API_TOKEN_ENCODE_AUDIENCE

    @property
    def decode_audience(self) -> Union[str, Iterable[str]]:
        return current_app.config.get("TOKEN_DECODE_AUDIENCE") or OCEANA_API_TOKEN_DECODE_AUDIENCE

    @property
    def identity_claim_key(self) -> str:
        return "sub"

    # Verifications
    @property
    def verify_sub(self) -> bool:
        return self._get_bool("TOKEN_VERIFY_SUB", OCEANA_API_TOKEN_VERIFY_SUB)

    @property
    def verify_version(self) -> bool:
        return self._get_bool("TOKEN_VERIFY_VERSION", OCEANA_API_TOKEN_VERIFY_VERSION)

    @property
    def register_auth(self) -> bool:
        return self._get_bool("REGISTER_AUTH", OCEANA_API_REGISTER_AUTH)

    @property
    def token_version(self):
        return OCEANA_API_TOKEN_VERSION

    def _get_bool(self, key: str, env_val) -> bool:
        if key in current_app.config:
            return bool(current_app.config.get(key))
        else:
            return bool(env_val)

    SWAGGER_UI_DOC_EXPANSION = "list"  # ("none", "list" or "full")

    # Default options, if you want to use other parameters in SqlAlchemy
    # use ConfigSqlAlchemy configuration instead of BaseConfig
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = False
    DB_SCHEMA = _config("DB_SCHEMA", default="public")

    # OAUTH2_PROVIDERS = {
    #     "azure": {
    #         "client_id": _config("AZURE_CLIENT_ID", ""),
    #         "client_secret": _config("AZURE_CLIENT_SECRET", ""),
    #         "authorize_url": _config("AZURE_AUTH_URL", ""),
    #         "access_token_url": _config("AZURE_TOKEN_URL", ""),
    #         "client_kwargs": {"scope": "openid email profile"},
    #         "jwks_uri": _config("AZURE_JWKS_URL", ""),

    #     },
    #     "google": {
    #         "client_id": _config("GOOGLE_CLIENT_ID", ""),
    #         "client_secret": _config("GOOGLE_CLIENT_SECRET", ""),
    #         "server_metadata_url": _config("GOOGLE_METADATA_URL", ""),
    #         "client_kwargs": {"scope": "openid email profile"}
    #     },
    #     "twitter": {
    #         "api_base_url": _config("OAUTH2_TWITTER_API_BASE_URL", ""),
    #         "request_token_url": _config("OAUTH2_TWITTER_REQUEST_TOKEN_URL", ""),
    #         "access_token_url": _config("OAUTH2_TWITTER_ACCESS_TOKEN_URL", ""),
    #         "authorize_url": _config("OAUTH2_TWITTER_AUTHORIZE_URL", ""),
    #         "userinfo_endpoint": _config("OAUTH2_TWITTER_USERINFO_ENDPOINT", ""),
    #         "userinfo_compliance_fix": _config("OAUTH2_TWITTER_USERINFO_COMPLIANCE_FIX", "")
    #     }
    # }


# Database Configuration POSTGRESQL
class Config(BaseConfig):
    # DB_HOST = _config("DB_HOST", default="127.0.0.1")
    # DB_NAME = _config("DB_NAME", default="oceana_jwt_auth")
    # DB_USERNAME = _config("DB_USERNAME", default="postgres")
    # DB_PASSWORD = _config("DB_PASSWORD", default="postgres")
    # DB_PORT = _config("DB_PORT", default="5432", cast=int)
    # DB_SCHEMA = _config("DB_SCHEMA", default="public")
    # DB_CREATE_ENTITIES = _config("DB_CREATE_ENTITIES", default=True, cast=bool)

    DB_HOST = _config("DB_HOST", default=None)
    DB_NAME = _config("DB_NAME", default=None)
    DB_USERNAME = _config("DB_USERNAME", default=None)
    DB_PASSWORD = _config("DB_PASSWORD", default=None)
    DB_PORT = _config("DB_PORT", default=5432, cast=int)
    DB_SCHEMA = _config("DB_SCHEMA", default="public")
    DB_CREATE_ENTITIES = _config("DB_CREATE_ENTITIES", default=True, cast=bool)


class ConfigSqlAlchemy(Config):
    # SQLAlchemy Configuration
    SQLALCHEMY_DATABASE_URI = _config("SQLALCHEMY_DATABASE_URI", None)
    SQLALCHEMY_ENGINE_OPTIONS = _config("SQLALCHEMY_ENGINE_OPTIONS", {})
    SQLALCHEMY_ECHO = _config("SQLALCHEMY_ECHO", None)
    SQLALCHEMY_BINDS = _config("SQLALCHEMY_BINDS", {})
    SQLALCHEMY_RECORD_QUERIES = _config("SQLALCHEMY_RECORD_QUERIES", None)
    SQLALCHEMY_TRACK_MODIFICATIONS = _config("SQLALCHEMY_TRACK_MODIFICATIONS", None)


# SQLAlchemy Postgres Configuration (overwrite properties)
class ConfigPostgres(ConfigSqlAlchemy):

    SQLALCHEMY_DATABASE_URI = ConfigSqlAlchemy.SQLALCHEMY_DATABASE_URI \
        if ConfigSqlAlchemy.SQLALCHEMY_DATABASE_URI is not None else \
        f"postgresql://{Config.DB_USERNAME}:{Config.DB_PASSWORD}" \
        f"@{Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}"
    SQLALCHEMY_ECHO = bool(ConfigSqlAlchemy.SQLALCHEMY_ECHO
                           if ConfigSqlAlchemy.SQLALCHEMY_ECHO is not None else False)
    SQLALCHEMY_TRACK_MODIFICATIONS = bool(ConfigSqlAlchemy.SQLALCHEMY_TRACK_MODIFICATIONS
                                          if ConfigSqlAlchemy.SQLALCHEMY_TRACK_MODIFICATIONS
                                          is not None else False)
    SQLALCHEMY_RECORD_QUERIES = bool(ConfigSqlAlchemy.SQLALCHEMY_RECORD_QUERIES
                                     if ConfigSqlAlchemy.SQLALCHEMY_RECORD_QUERIES
                                     is not None else False)


# SQLAlchemy SQLite Configuration (overwrite properties)
# Used in tests
class ConfigSqlite(ConfigSqlAlchemy):

    # SQLALCHEMY_DATABASE_URI = "sqlite:///project.db"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    DB_HOST = None
    DB_NAME = None
    DB_USERNAME = None
    DB_PASSWORD = None
    DB_PORT = None
    # Default value to test
    DB_SCHEMA = "public"
    DB_CREATE_ENTITIES = True


# Syntax sugar: Shared instance of Config class just to get the
# properties (@property label) from the Flask current_app.
config = Config()
