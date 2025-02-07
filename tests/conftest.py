import pytest
from flask import Flask, Blueprint, jsonify
from flask_restx import Api, Namespace, Resource

from oceana_jwt_auth import JWTExtension, ConfigSqlite, authorizations, security, \
    OCEANA_API_PROVIDER, db, get_endpoint_security_dict, info, auth_guard
from oceana_jwt_auth.models import SecIdentity, SecEndpoint

from oceana_jwt_auth.utils.constants import ENDPOINT_SECURITY_LABEL


def _populate_endpoint_security_data(session):
    endpoints = [
        # For pytest
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="_test_app.<locals>.test_me",
            roles="reader",
            url_template="/v1/test",
            description="Test Endpoint"),
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="_test_app.<locals>.test_optional",
            roles="reader",
            url_template="/v1/optional",
            description="Test Endpoint"),
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="_test_app.<locals>.test_free_pass",
            roles="all",
            url_template="/v1/free_pass",
            description="Test Endpoint"),
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="_test_app.<locals>.raise_me",
            roles="all",
            url_template="/v1/raise",
            description="Test Endpoint"),
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="_test_app.<locals>.fail_validation",
            roles="all",
            url_template="/v1/fail",
            description="Test Endpoint"),
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="_test_app.<locals>.test_admin",
            roles="admin",
            url_template="/v1/admin",
            description="Test Endpoint"),
        # To test routing with class in test_application.py
        SecEndpoint(
            provider=OCEANA_API_PROVIDER,
            endpoint="TestApp.get",
            roles="reader",
            url_template="/v1/test",
            description="Test Endpoint"),
    ]

    for endpoint in endpoints:
        session.add(endpoint)
    session.commit()


def _populate_identity_data(session):
    identities = [
        SecIdentity(
            provider=OCEANA_API_PROVIDER,
            client_type="application",
            client_id="oceana-admin",
            # client_secret = "bad_password"
            client_hash="e63fb8fb1bc2de9836798fb9eb87b393fc0c6e23506ed5ad962e3140c9582fa1",
            client_salt="f19t70fRqbeKRgdB9LdoW1wf0o5oT_eLSPNotue4GsM=",
            roles="admin",
            enabled=True),
        SecIdentity(
            provider=OCEANA_API_PROVIDER,
            client_type="application",
            client_id="oceana-reader",
            # client_secret = "bad_password"
            client_hash="546f797e7465aa179c42df05ff7c6842988ed82f84e18a9a0bd6c75828d3d838",
            client_salt="2yInlAvKMJvJMKjnTBV_bgiHsvCkcnt0kuGVXqxSGv4=",
            roles="reader",
            enabled=True),
        SecIdentity(
            provider=OCEANA_API_PROVIDER,
            client_type="application",
            client_id="oceana-writer",
            # client_secret = "bad_password"
            client_hash="ac193d5ef24419e3ab3afaac5614a0eaf95597e1a77116440eb2cc8d68fc536e",
            client_salt="A-vbqAXkos6geH3-q6dwciVH6cbLRziOCPyJp4A8PLM=",
            roles="reader,writer",
            enabled=True),
    ]
    for identity in identities:
        session.add(identity)
    session.commit()


@pytest.fixture(scope="function")
def flask_app():
    """
    Fixture of Flask application with SQLite database configuration.
    Only has created the registration endpoint.
    """

    yield _create_flask_app()


def _create_flask_app():

    app = Flask(__name__)
    bp = Blueprint("api", __name__)
    api = Api(
        bp,
        authorizations=authorizations,
        security=security,
        title="Oceana Test API",
        version="1.0",
        description="Oceana Test API",
    )
    app.register_blueprint(bp)

    app.config["SECURED"] = True
    app.config["REGISTER_AUTH"] = True

    JWTExtension(app, api, config_object=ConfigSqlite)

    with app.app_context():
        _populate_endpoint_security_data(db.session)
        _populate_identity_data(db.session)

        # Get endpoint security from database
        endpoint_security = get_endpoint_security_dict(provider=OCEANA_API_PROVIDER)
        app.config[ENDPOINT_SECURITY_LABEL] = endpoint_security
        info(f"app.config[\"{ENDPOINT_SECURITY_LABEL}\"]: {endpoint_security}")
        assert len(endpoint_security) > 0, "Endpoint security is not populated"

    app.testing = True
    return app


def _test_app(app: Flask):

    # @app.errorhandler(Exception)
    # def internal_server_error(e):
    #     return jsonify({"error": str(e)}), 500

    # roles="reader"
    @app.route("/v1/test")
    @auth_guard(secured=True)
    def test_me():
        return jsonify({"status": "OK", "code": 200})

    # roles="reader"
    @app.route("/v1/optional")
    @auth_guard(secured=True, optional=True)
    def test_optional():
        return jsonify({"status": "OK", "code": 200})

    # roles="all"
    @app.route("/v1/free_pass")
    @auth_guard(secured=True)
    def test_free_pass():
        return jsonify({"status": "OK", "code": 200})

    # roles="admin"
    @app.route("/v1/admin")
    @auth_guard(admin=True)
    def test_admin():
        return jsonify({"status": "OK", "code": 200})

    # roles not configured in DB, only admin
    @app.route("/v1/admin_only")
    @auth_guard(admin=True)
    def test_admin_only():
        return jsonify({"status": "OK", "code": 200})

    # roles="all"
    @app.route("/v1/raise")
    @auth_guard(secured=True)
    def raise_me():
        raise Exception("Exception from decorated method")

    # roles="all"
    @app.route("/v1/fail")
    @auth_guard(secured=True)
    def fail_validation():
        raise BaseException("Raised base exception")

    return app


@pytest.fixture(scope="function")
def test_app():
    """
    Fixture of Flask application with SQLite database configuration.
    It has the application endpoints to test and the registration one.
    """

    app = _create_flask_app()
    yield _test_app(app)


# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")

jwt = JWTExtension(config_object=ConfigSqlite)
app = jwt.init_app()
api = jwt.api()

with app.app_context():
    _populate_endpoint_security_data(db.session)
    _populate_identity_data(db.session)

    # Get endpoint security from database
    endpoint_security = get_endpoint_security_dict(provider=OCEANA_API_PROVIDER)
    app.config[ENDPOINT_SECURITY_LABEL] = endpoint_security
    info(f"app.config[\"{ENDPOINT_SECURITY_LABEL}\"]: {endpoint_security}")
    assert len(endpoint_security) > 0, "Endpoint security is not populated"

app.testing = True


# roles="reader"
@ns_test.route("/test", methods=["GET"])
class TestApp(Resource):
    @auth_guard(secured=True)
    def get(self):
        return jsonify({"status": "OK", "code": 200})


# Add namespace
api.add_namespace(ns_test)


# Test application defined in a class (TestApp)
@pytest.fixture(scope="function")
def test_app_classdef():
    """
    Fixture of Flask application with SQLite database configuration.
    It has the application endpoints to test and the registration one.
    """

    yield app


def _create_flask_app_not_secured():

    app = Flask(__name__)
    bp = Blueprint("api", __name__)
    api = Api(
        bp,
        authorizations=authorizations,
        security=security,
        title="Oceana Test API",
        version="1.0",
        description="Oceana Test API",
    )
    app.register_blueprint(bp)

    app.config["SECURED"] = False
    app.config["REGISTER_AUTH"] = False

    JWTExtension(app, api, config_object=ConfigSqlite)

    with app.app_context():
        _populate_endpoint_security_data(db.session)
        _populate_identity_data(db.session)

        # Get endpoint security from database
        endpoint_security = get_endpoint_security_dict(provider=OCEANA_API_PROVIDER)
        app.config[ENDPOINT_SECURITY_LABEL] = endpoint_security
        info(f"app.config[\"{ENDPOINT_SECURITY_LABEL}\"]: {endpoint_security}")
        assert len(endpoint_security) > 0, "Endpoint security is not populated"

    app.testing = True
    return app


@pytest.fixture(scope="function")
def test_app_not_secured():
    """
    Fixture of Flask application with SQLite database configuration.
    It has the application endpoints to test and the registration one.
    """

    app = _create_flask_app_not_secured()
    yield _test_app(app)
