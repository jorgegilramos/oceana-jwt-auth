"""
JWT Extension
"""
from datetime import timedelta
from typing import Optional, Callable, Any, List, Tuple, Dict, Union

from flask import Blueprint, Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api
# from flask_wtf.csrf import CSRFProtect

from .config import Config, OCEANA_API_PROVIDER
from .utils import info, debug, EXTENSION_NAME, EXTENSION_BIND, ENDPOINT_SECURITY_LABEL, \
    API_AUTH_DEFAULT_TITLE, API_AUTH_DEFAULT_VERSION, API_AUTH_DEFAULT_DESCRIPTION
from .internals import default_user_claims_callback, default_token_header_callback, \
    default_token_verification_callback, default_encode_key_callback, \
    default_decode_key_callback
from .auth import authorizations, security, register_auth_namespace
from .database.db import db, init_app
from .database.auth_repository import get_endpoint_security_dict
from .jwt_handler import encode_jwt, decode_jwt, decode_jwt_unverified


class JWTExtension():
    """
    JWTExtension
    """

    def __init__(self,
                 app: Optional[Flask] = None,
                 api: Optional[Api] = None,
                 config_object: Optional[Callable] = None,
                 declarative_base: SQLAlchemy = None,
                 *args,
                 **kwargs):
        """
        Create an jwt authorization helper for a application.

        :param Flask app:
            It can be a Flask app instance, or ``None``.

            1. Use your globally avalaible app object.

            2. But if you are using `Application Factory pattern
            <https://flask.palletsprojects.com/en/latest/patterns/appfactories/>`,
            your app is not available globally, so you need to pass ``None`` here,
            and call :func:`JWTExtension.init_app()` later,
        :param Api api:
            Api Flask RestX instance, or ``None``.
            If app object is passed, it is mandatory to provide Api object as well

        """

        # Store config object
        self._config = config_object() if config_object is not None else Config()

        # Define callback for verification token function
        self._token_verification_callback = default_token_verification_callback
        self._user_claims_callback = default_user_claims_callback
        self._encode_key_callback = default_encode_key_callback
        self._decode_key_callback = default_decode_key_callback
        self._token_header_callback = default_token_header_callback

        if app is not None:
            self.init_app(app, api, config_object, declarative_base, *args, **kwargs)

    def init_app(self,
                 app: Optional[Flask] = None,
                 api: Optional[Api] = None,
                 config_object: Optional[Callable] = None,
                 declarative_base: SQLAlchemy = None,
                 *args,
                 **kwargs) -> Flask:
        """
        Register this extension with the flask app.

        :param app:
            The Flask Application object
        :param api:
            Flask RestX Api instance
        """

        if app is not None and EXTENSION_NAME in app.extensions:
            raise RuntimeError(
                f"A \"{EXTENSION_NAME}\" instance has already been registered on this Flask app."
                " Import and use that instance instead."
            )

        if app is None:
            # Create flask application if it is not provided
            app = Flask(__name__)
            if api is None:
                bp = Blueprint(f"{EXTENSION_NAME}_app", __name__)
                api = self.create_api(bp, **kwargs)
                app.register_blueprint(bp)
        elif api is None:
            raise Exception("Api parameter can't be empty when app is specified")

        # Store config object
        if config_object is not None:
            self._config = config_object()

        # Store Api instance
        self._app = app
        self._api = api

        # Add authorization configuration
        api.authorizations = authorizations
        api.security = security

        app = self._create_app(app, api, config_object, declarative_base, *args, **kwargs)

        # Check extension property
        app.extensions = {} if not hasattr(app, "extensions") else app.extensions
        app.extensions[EXTENSION_NAME] = self
        return app

    def create_api(self, bp=None, **kwargs):
        _title = kwargs.get("title") or API_AUTH_DEFAULT_TITLE
        _version = kwargs.get("version") or API_AUTH_DEFAULT_VERSION
        _description = kwargs.get("description") or API_AUTH_DEFAULT_DESCRIPTION
        api = Api(
            app=bp,
            authorizations=authorizations,
            security=security,
            title=_title,
            version=_version,
            description=_description
        )
        return api

    def _create_app(self,
                    app: Flask,
                    api: Api,
                    config_object: Optional[Callable] = None,
                    declarative_base: SQLAlchemy = None,
                    *args,
                    **kwargs):
        # Default config is Config
        if not config_object:
            config_object = Config
            self._config = Config()

        # Get properties from object. SQLAlchemy properties are taken from
        # the Flask application overriding those ones coming from the object.
        # app.config.from_object(config_object())
        self._app_config_from_object(app, config_object)

        # TODO: Init other extensions
        # csrf.init_app(app)
        # oauth.init_app(app)
        # register_oauth_clients(app)

        # Init database context
        if declarative_base is None:
            declarative_base = db

        # Initialize SQLAlchemy application
        if "sqlalchemy" not in app.extensions:
            declarative_base.init_app(app)

        # self._declarative_base = declarative_base

        with app.app_context():
            testing = hasattr(app, "testing") and bool(app.testing)
            debug(f"Testing: {testing}")

            # Show information about global security
            info(f"API secured: {self._config.api_secured}")

            # Create all necessary database entities
            init_app(config_object, testing, declarative_base)

            # Get endpoint security from database
            self.update_auth_from_db()

            # Register authorization namespace (need context)
            if self._config.register_auth:
                bp = Blueprint(f"{EXTENSION_NAME}_api", __name__, url_prefix="/")
                register_auth_namespace(api=api)
                app.register_blueprint(bp)
            info(f"Registered authorization endpoints: {self._config.register_auth}")

        return app

    def _app_config_from_object(self,
                                app: Flask,
                                config_object: Optional[Callable] = None):
        sqlalchemy_keys = ["SQLALCHEMY_DATABASE_URI",
                           "SQLALCHEMY_ENGINE_OPTIONS",
                           "SQLALCHEMY_ECHO",
                           "SQLALCHEMY_BINDS",
                           "SQLALCHEMY_RECORD_QUERIES",
                           "SQLALCHEMY_TRACK_MODIFICATIONS"]

        obj = config_object()
        for key in dir(obj):
            if key.isupper():
                if key not in sqlalchemy_keys:
                    value = getattr(obj, key)
                else:
                    value = getattr(obj, key) if not app.config.get(key) \
                        else app.config[key]
                app.config[key] = value
                setattr(self._config, key, value)

        # Ensure oceana_jwt_auth bind
        if (_binds := app.config.get("SQLALCHEMY_BINDS")) is None:
            app.config["SQLALCHEMY_BINDS"] = \
                {EXTENSION_BIND: app.config["SQLALCHEMY_DATABASE_URI"]}
        elif EXTENSION_BIND not in _binds:
            app.config["SQLALCHEMY_BINDS"].update(
                {EXTENSION_BIND: app.config["SQLALCHEMY_DATABASE_URI"]}
            )

    def update_auth_from_db(self):

        # Get endpoint security from database
        secured_endpoints = get_endpoint_security_dict(provider=OCEANA_API_PROVIDER)
        self._app.config[ENDPOINT_SECURITY_LABEL] = secured_endpoints
        setattr(self._app.config, ENDPOINT_SECURITY_LABEL, secured_endpoints)
        info(f"Secured endpoints: {len(secured_endpoints)}")
        # Show security endpoints information from database when the application is started
        for endpoint_id in secured_endpoints:  # pragma: no cover
            roles = secured_endpoints[endpoint_id].get("roles")
            info(f"    - {endpoint_id}: {roles}")
        debug(f"Endpoint security: {secured_endpoints}")

    def config(self) -> Config:
        """
        Get extension configuration instance
        """
        return self._config

    def api(self) -> Api:
        """
        Get application Api instance (Flask RestX)
        """
        return self._api

    # Decorated functions to override default behaviour
    def set_token_verification_function(self, callback: Callable) -> Callable:
        """
        Decorator function. Sets the callback function used for custom
        verification of a valid JWT.

        Decorated function:
            Must take six arguments.

        :param str endpoint_id: Argument indicating the endpoint identificator.
        :param dict jwt_header: Dictionary containing the header data of the JWT.
        :param dict jwt_data: Dictionary containing the payload data of the JWT.
        :param bool optional: Boolean ``True`` if JWT is optional in the endpoint
            ``False`` otherwise.
        :param list allowed: List of roles allowed for the endpoint.
        :param list roles: List of roles from the valid JWT

        :return None:
        """

        self._token_verification_callback = callback
        return callback

    def set_user_claims_function(self, callback: Callable) -> Callable:
        """
        Decorator function. Sets the callback function used to add custom
        user claims in a JWT.
        The dictionary of claims returned in the decorated function will be
        added to claims in JWT that were passed in parameter in ``additional_claims``
        when creating the access token. Parameter ``additional_claims`` override
        claims in case of name coincidence.

        Decorated function:
            Must take only one argument.

        :param str identity:
            Argument indicating the endpoint identificator.

        :return dict user_claims:
            Dictionary with custom user claims in a JWT.
        """

        self._user_claims_callback = callback
        return callback

    def set_token_header_function(self, callback: Callable) -> Callable:
        """
        Decorator function. Sets the callback function used to add custom user
        properties to the header in a JWT.

        Decorated function:
            Must take only one argument.

        :param str header: Argument indicating headers to add.

        :return dict header_properties:
            Dictionary with custom properties to the header in a JWT.
        """

        self._token_header_callback = callback
        return callback

    def _encode_jwt_from_config(
        self,
        identity: Any,
        roles: List[str],
        token_type: str,
        claims=None,
        expires_delta: Optional[timedelta] = None,
        headers=None,
        version=None,
        payload: dict = {}
    ) -> Tuple[str, Dict]:
        # Override headers
        add_headers = self._token_header_callback(headers)
        if headers is not None:
            add_headers.update(headers)

        # Override claims
        add_claims = self._user_claims_callback(identity)
        if claims is not None:
            add_claims.update(claims)

        config = self._config  # self.config()
        if expires_delta is None:
            if token_type == "access":
                expires_delta = config.access_token_delta
            # TODO: implement refresh tokens
            # else:
            #     expires_delta = config.refresh_token_delta

        if version is None and config.token_version is not None:
            version = config.token_version

        return encode_jwt(
            algorithm=config.algorithm,
            audience=config.encode_audience,
            claim_overrides=add_claims,
            expires_delta=expires_delta,
            header_overrides=add_headers,
            identity=identity,
            identity_claim_key=config.identity_claim_key,
            issuer=config.encode_issuer,
            roles=roles,
            secret=self._encode_key_callback(identity, config.algorithm),
            token_type=token_type,
            nbf=True,
            version=version,
            payload=payload
        )

    def _decode_jwt_from_config(
        self,
        token: Union[str, None],
        version=None,
    ) -> Tuple[Dict, Dict]:
        """
        Called from verify_jwt_request
        """

        config = self._config
        algorithms = [config.algorithm]
        key = self._decode_key_callback(identity=None, algorithm=config.algorithm)

        if version is None and config.token_version is not None:
            version = config.token_version

        return decode_jwt(
            algorithms=algorithms,
            audience=config.decode_audience,
            token=token,
            identity_claim_key=config.identity_claim_key,
            issuer=config.decode_issuer,
            key=key,
            version=version,
            verify_aud=config.decode_audience is not None,
            verify_sub=config.verify_sub,
            verify_version=config.verify_version)

    def _decode_jwt_unverified_from_config(
        self,
        token: str
    ) -> Tuple[Dict, Dict]:
        """
        Tries to retrieve and header and payload information inside of a existent JWT token (string)
        """
        algorithms = [self._config.algorithm]
        return decode_jwt_unverified(
            algorithms=algorithms,
            token=token
        )
