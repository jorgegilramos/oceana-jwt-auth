import pytest
from flask import Blueprint, Flask, jsonify
from flask_restx import Namespace, Resource, Api
from http import HTTPStatus

from oceana_jwt_auth import JWTExtension, ConfigSqlite, \
    auth_guard, authorizations, security
from oceana_jwt_auth.utils import EXTENSION_NAME
from oceana_jwt_auth.internals import get_jwt_extension


def test_app_blueprint_registration():
    # Create namespace
    ns_test = Namespace("Test", description="Test API", path="/test")

    @ns_test.route("/", methods=["GET"])
    class TestApp(Resource):
        @auth_guard(secured=True)
        def get(self):
            return jsonify({"status": "OK", "code": 200})

    bp = Blueprint("api", __name__)
    api = Api(
        bp,
        authorizations=authorizations,
        security=security,
        title="Oceana Test API",
        version="1.0",
        description="Oceana Test API",
    )

    # Add namespaces
    api.add_namespace(ns_test)

    # Flask app instance
    app = Flask(__name__)
    app.config["SECURED"] = True
    app.config["REGISTER_AUTH"] = True

    # Register blueprint
    app.register_blueprint(bp)

    JWTExtension(app=app, api=api, config_object=ConfigSqlite)

    # Test route /test
    test_client = app.test_client()
    response = test_client.get("/test/")
    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.headers.get("WWW-Authenticate") is None
    assert response.get_json() == {"status": "OK", "code": 200}


def test_initialize_api_empty_error():
    app = Flask(__name__)
    # Validate exception
    with pytest.raises(Exception) as exc_info:
        JWTExtension(app=app)
    assert str(exc_info.value) == "Api parameter can't be empty when app is specified"


def test_get_jwt_extension():

    app = Flask(__name__)
    with app.test_request_context():
        with pytest.raises(RuntimeError) as exc_info:
            # Get extension
            get_jwt_extension()

        assert str(exc_info.value) == \
            "JWTExtension must be initialized in application before using this method"


def test_extension_already_registered():
    app = Flask(__name__)
    # Create authorization extension
    jwt = JWTExtension()
    app = jwt.init_app()
    # Validate exception
    with pytest.raises(RuntimeError) as exc_info:
        app = jwt.init_app(app=app)
    assert str(exc_info.value) == f"A \"{EXTENSION_NAME}\" instance has already been registered " + \
        "on this Flask app. Import and use that instance instead."


def test_initialize_factory_ok():

    # Configuration including registration
    class ConfigAuth(ConfigSqlite):
        REGISTER_AUTH = True

    # App is not available globally (Application Factory pattern)
    # Create authorization extension
    jwt = JWTExtension()
    # Create flask app without Api object
    app = jwt.init_app(config_object=ConfigAuth)

    # Rules
    bp_name = "oceana-jwt-auth_app"
    rule_endpoint = [
        ("/static/<path:filename>", "static"),
        ("/swagger.json", f"{bp_name}.specs"),
        ("/", f"{bp_name}.doc"),
        ("/", f"{bp_name}.root"),
        ("/swaggerui/<path:filename>", "restx_doc.static"),
        ("/auth/token", f"{bp_name}.Auth_get_token")
    ]

    assert isinstance(jwt, JWTExtension)
    for rule in app.url_map._rules:
        # Check if rule exist
        assert (rule.rule, rule.endpoint) in rule_endpoint

    assert len(app.url_map._rules) == 6


def test_initialize_auth_rules():
    # Create namespace
    ns_test = Namespace("Test", description="Test API", path="/v1/test")

    @ns_test.route("/", methods=["GET"])
    class TestApp(Resource):
        @auth_guard(secured=True)
        def get(self):
            return jsonify({"status": "OK", "code": 200})

    bp_name = "api"
    bp = Blueprint(bp_name, __name__)
    api = Api(
        bp,
        authorizations=authorizations,
        security=security,
        title="Oceana Test API",
        version="1.0",
        description="Oceana Test API",
    )

    # # Add namespaces
    api.add_namespace(ns_test)

    # Flask app instance
    app = Flask(__name__)
    app.config["SECURED"] = True
    app.config["REGISTER_AUTH"] = True
    jwt = JWTExtension(app=app, api=api, config_object=ConfigSqlite)
    # Register blueprint
    app.register_blueprint(bp)

    # Rules
    rule_endpoint = [
        ("/static/<path:filename>", "static"),
        ("/swagger.json", f"{bp_name}.specs"),
        ("/", f"{bp_name}.doc"),
        ("/", f"{bp_name}.root"),
        ("/swaggerui/<path:filename>", "restx_doc.static"),
        ("/v1/test/", f"{bp_name}.Test_test_app"),
        ("/auth/token", f"{bp_name}.Auth_get_token")
    ]

    assert isinstance(jwt, JWTExtension)
    for rule in app.url_map._rules:
        # Check if rule exist
        assert (rule.rule, rule.endpoint) in rule_endpoint

    assert len(app.url_map._rules) == 7

    # Test route /test
    test_client = app.test_client()
    response = test_client.get("/v1/test/")
    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.headers.get("WWW-Authenticate") is None
    assert response.get_json() == {"status": "OK", "code": 200}
