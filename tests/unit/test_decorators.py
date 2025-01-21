import pytest
from http import HTTPStatus

from flask import Flask, jsonify

from oceana_jwt_auth import auth_guard, \
    get_jwt, get_identity

from .. import generate_test_token


def test_get_jwt_no_auth_guard_error(flask_app: Flask):

    with flask_app.test_request_context():
        with pytest.raises(RuntimeError) as exc_info:
            get_jwt()
    assert str(exc_info.value) == "You must call `@auth_guard()` before using this method"


def test_get_jwt_ok(flask_app: Flask):

    @flask_app.route("/test_me")
    @auth_guard(secured=False)
    def test_me():
        oceana_jwt = get_jwt()
        roles = oceana_jwt.get("roles")
        client_id = get_identity()
        return jsonify({"status": "OK", "code": 200, "client_id": client_id, "roles": roles})

    test_client = flask_app.test_client()

    token = generate_test_token(
        app=flask_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    url = "/test_me"
    response = test_client.get(url, headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {
        "status": "OK",
        "code": 200,
        "client_id": "oceana-reader",
        "roles": ["reader"]
    }


def test_decode_unverified_jwt_request(test_app: Flask):

    test_client = test_app.test_client()

    url = "/v1/optional"
    response = test_client.get(url, headers={})

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}


def test_classdef_get_jwt_ok(test_app_classdef: Flask):

    test_client = test_app_classdef.test_client()

    token = generate_test_token(
        app=test_app_classdef,
        identity="oceana-reader",
        roles=["reader"]
    )

    url = "/v1/test"
    response = test_client.get(url, headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}
