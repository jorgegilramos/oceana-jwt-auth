import pytest
from flask import Flask
from flask import json, Response
from http import HTTPStatus

from oceana_jwt_auth import handle_exceptions

from oceana_jwt_auth.api.common import response_api_ok, response_api_error
from oceana_jwt_auth.exceptions import HttpResponseError, ClientAuthenticationError, \
    ClientBadRequestException


def _create_errors_app(app: Flask):

    app.config["REGISTER_AUTH"] = False

    @app.route("/response_error", methods=["GET"])
    @handle_exceptions()
    def response_error():
        raise HttpResponseError(status_code=int(HTTPStatus.BAD_REQUEST.value),
                                error="error_type",
                                message="Error message")

    @app.route("/client_authentication_error", methods=["GET"])
    @handle_exceptions()
    def client_authentication_error():
        raise ClientAuthenticationError("Client authentication error message")

    @app.route("/client_bad_request_error", methods=["GET"])
    @handle_exceptions()
    def client_bad_request_error():
        raise ClientBadRequestException("Client bad request error message")

    @app.route("/raise_exception", methods=["GET"])
    @handle_exceptions()
    def raise_exception():
        raise Exception("Raise exception")

    @app.route("/raise_base_exception")
    @handle_exceptions()
    def raise_base_exception():
        raise BaseException("Raised base exception")

    @app.route("/test_ok", methods=["GET"])
    @handle_exceptions()
    def test_ok():
        return response_api_ok(http_code=int(HTTPStatus.OK.value),
                               data={},
                               endpoint="test_ok")

    @app.route("/test_error", methods=["GET"])
    @handle_exceptions()
    def test_error():
        return response_api_error(http_code=int(HTTPStatus.BAD_REQUEST.value),
                                  error="Test error message",
                                  endpoint="test_error")

    @app.route("/test_custom_error", methods=["GET"])
    @handle_exceptions()
    def test_custom_error():
        response = Response(
            response=json.dumps({}),
            status=int(HTTPStatus.INTERNAL_SERVER_ERROR.value),
            mimetype="application/json"
        )
        response.reason = "Error reason"
        raise HttpResponseError(status_code=int(HTTPStatus.BAD_REQUEST.value),
                                error="error_type",
                                message="Error message",
                                response=response)

    return app


@pytest.fixture(scope="function")
def test_errors_app(flask_app: Flask):

    yield _create_errors_app(flask_app)


# Tests to check
def test_response_error(test_errors_app: Flask):

    url = "/response_error"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)

    assert response.status_code == int(HTTPStatus.BAD_REQUEST.value)
    assert response.headers["WWW-Authenticate"]
    assert response.headers["WWW-Authenticate"] == \
        "Bearer error=\"error_type\" " + \
        "error_description=\"Error message\""


def test_client_authentication_error(test_errors_app: Flask):

    url = "/client_authentication_error"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)

    assert response.status_code == int(HTTPStatus.UNAUTHORIZED.value)
    assert response.headers["WWW-Authenticate"]
    assert response.headers["WWW-Authenticate"] == \
        "Bearer error=\"invalid_token\" " + \
        "error_description=\"Client authentication error message\""


def test_client_bad_request_error(test_errors_app: Flask):

    url = "/client_bad_request_error"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)

    assert response.status_code == int(HTTPStatus.BAD_REQUEST.value)
    assert response.headers["WWW-Authenticate"]
    assert response.headers["WWW-Authenticate"] == \
        "Bearer error=\"invalid_request\" " + \
        "error_description=\"Client bad request error message\""


def test_raise_exception(test_errors_app: Flask):

    url = "/raise_exception"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)

    assert response.status_code == int(HTTPStatus.INTERNAL_SERVER_ERROR.value)
    assert response.headers["WWW-Authenticate"]
    assert response.headers["WWW-Authenticate"] == "Raise exception"


def test_raise_base_exception(test_errors_app: Flask):

    url = "/raise_base_exception"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)

    assert response.status_code == int(HTTPStatus.UNAUTHORIZED.value)
    assert response.headers["WWW-Authenticate"]
    assert "Bearer error=\"invalid_token\" " + \
        "error_description=\"Token validation failed\"" \
        == response.headers["WWW-Authenticate"]


def test_ok(test_errors_app: Flask):

    url = "/test_ok"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)
    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.headers.get("WWW-Authenticate") is None
    assert response.get_json() == {"status": "OK", "code": 200, "endpoint": "test_ok"}


def test_error(test_errors_app: Flask):

    url = "/test_error"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)
    assert response.status_code == int(HTTPStatus.BAD_REQUEST.value)
    assert response.headers.get("WWW-Authenticate") is None
    assert response.get_json() == {
        "code": 400,
        "endpoint": "test_error",
        "error": "Test error message",
        "status": "ERROR"
    }


def test_custom_error(test_errors_app: Flask):

    url = "/test_custom_error"
    test_client = test_errors_app.test_client()
    response = test_client.get(url)
    assert response.status_code == int(HTTPStatus.INTERNAL_SERVER_ERROR.value)
    assert response.headers.get("WWW-Authenticate") == "Bearer error=\"error_type\" error_description=\"Error message\""
    assert response.get_json() == {
        "code": 500,
        "endpoint": "_create_errors_app.<locals>.test_custom_error",
        "error": "Bearer error=\"error_type\" error_description=\"Error message\"",
        "status": "ERROR"
    }
