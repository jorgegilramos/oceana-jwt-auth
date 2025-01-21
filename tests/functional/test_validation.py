from flask import Flask
from http import HTTPStatus

from .. import generate_test_token, mock_test_token_payload


def _expect_valid_token(response):

    # Status 200
    assert response.status_code == int(HTTPStatus.OK.value)


def _expect_internal_server_error(response, error_msg):

    # Status 500
    assert response.status_code == int(HTTPStatus.INTERNAL_SERVER_ERROR.value)
    assert response.get_json()["error"] == error_msg


def _expect_invalid_token(response, msg):

    # Status 401
    assert response.status_code == int(HTTPStatus.UNAUTHORIZED.value)
    assert response.headers["WWW-Authenticate"]
    assert response.headers["WWW-Authenticate"] == \
        "Bearer error=\"invalid_token\" " + \
        f"error_description=\"{msg}\""


def _expect_invalid_request(response, msg):

    # Status 400
    assert response.status_code == int(HTTPStatus.BAD_REQUEST.value)
    assert response.headers["WWW-Authenticate"]
    assert response.headers["WWW-Authenticate"] == \
        "Bearer error=\"invalid_request\" " + \
        f"error_description=\"{msg}\""


# Tests to check
def test_authentication_endpoint(test_app: Flask):

    _headers = {
        "Content-Type": "application/json"
    }
    json_data_ok = {
        "client_id": "oceana-reader",
        "client_secret": "bad_password"
    }
    response = test_app.test_client().post("/auth/token", json=json_data_ok, headers=_headers)

    _expect_valid_token(response)


def test_request_without_headers(test_app):

    response = test_app.test_client().get("/v1/test")

    _expect_invalid_request(response, "Authorization header missing")


def test_request_with_empty_authorization_header(test_app):

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": ""
    })

    _expect_invalid_request(response, "Authorization header missing")


def test_request_missing_token(test_app: Flask):

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": "Bearer"
    })

    _expect_invalid_request(response, "Bearer access token missing")


def test_request_wrong_auth(test_app: Flask):

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": "Basic not_a_valid_token"
    })

    _expect_invalid_request(response, "Basic authorization is not allowed in JWT")


def test_request_wrong_syntax(test_app: Flask):

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": "Bearer not_a_valid_token"
    })

    _expect_invalid_request(response, "Invalid token format")


def test_request_wrong_authorization_method(test_app: Flask):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )
    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"AuthNotAllowed {token}"
    })

    _expect_invalid_request(response, "Authorization header must follow pattern \"Bearer <token_value>\"")


def test_valid_token(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_valid_token(response)


def test_optional_ok(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-user",
        roles=[]
    )

    response = test_app.test_client().get("/v1/optional", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_valid_token(response)


def test_optional_invalid_issuer(test_app):

    token = mock_test_token_payload(
        identity="oceana-user",
        roles=[],
        payload={"iss": "not-my-issuer"}  # No issuer
    )

    response = test_app.test_client().get("/v1/optional", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_invalid_token(response, "Invalid access token: Invalid issuer")


def test_admin_token_ok(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-admin",
        roles=["admin"]
    )

    response = test_app.test_client().get("/v1/admin", headers={
        "Authorization": f"Bearer {token}"
    })
    _expect_valid_token(response)


def test_admin_token_error(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    response = test_app.test_client().get("/v1/admin", headers={
        "Authorization": f"Bearer {token}"
    })
    _expect_invalid_token(response, "Only an admin can access to this route")


def test_admin_only_error(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    response = test_app.test_client().get("/v1/admin_only", headers={
        "Authorization": f"Bearer {token}"
    })
    _expect_invalid_token(response, "Only an admin can access to this route")


def test_admin_only_ok(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-admin",
        roles=["admin"]
    )

    response = test_app.test_client().get("/v1/admin_only", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_valid_token(response)


def test_invalid_token_corrupt_header(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    # Corrupt token (Invalid crypto padding)
    token = ".".join(token.split(".")[:-1]) + ".error"
    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_invalid_request(response, "Invalid access token: Invalid crypto padding")


def test_invalid_token_signature_failed(test_app):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    # Change signature (Signature verification failed)
    token = ".".join(token.split(".")[:-1]) + "._ru9Bulj-0xTScS8rlxJGnPlIhK0WKttacDCAUiSOMM"
    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_invalid_request(response, "Invalid access token: Signature verification failed")


def test_invalid_issuer(test_app: Flask):

    token = mock_test_token_payload(
        identity="oceana-reader",
        roles=["reader"],
        payload={"iss": "not-my-issuer"}
    )

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_invalid_token(response, "Invalid access token: Invalid issuer")


def test_decorated_method_raises_exception(test_app: Flask):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    response = test_app.test_client().get("/v1/raise", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_internal_server_error(response, "Exception from decorated method")


def test_decorated_method_raises_base_exception(test_app: Flask):

    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    response = test_app.test_client().get("/v1/fail", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_invalid_token(response, "Token validation failed")


def test_expired_token(test_app: Flask):

    token = mock_test_token_payload(
        identity="oceana-reader",
        roles=["reader"],
        payload={
            "iat": 1,
            "exp": 2
        }
    )
    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    _expect_invalid_token(response, "Invalid access token: Signature has expired")
