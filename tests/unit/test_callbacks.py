from http import HTTPStatus
from flask import Flask
# from oceana_jwt_auth import auth_guard
from oceana_jwt_auth.internals import get_jwt_extension, is_authorized
from oceana_jwt_auth.exceptions import ClientAuthenticationError, \
    ClientBadRequestException

from .. import generate_test_token, create_access_token


def test_default_token_verification_function(test_app: Flask):

    # Check token response for "reader" role
    token = generate_test_token(
        app=test_app,
        identity="oceana-user",
        roles=["role-cant-access"]
    )

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.UNAUTHORIZED.value)
    assert response.get_json()["error"] == "Bearer error=\"invalid_token\" error_description=\"Authorization required\""

    # Optional without authorization
    response = test_app.test_client().get("/v1/optional", headers={
        "Authorization": ""
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}

    # Check token format response ok in optional
    response = test_app.test_client().get("/v1/optional", headers={
        "Authorization": "whatever"
    })
    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}

    # Check token response "/v1/test" for "admin" role
    token = generate_test_token(
        app=test_app,
        identity="oceana-admin",
        roles=["admin"]
    )

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}


def test_default_token_verification_all(test_app: Flask):

    # Check token response for "all"
    token = generate_test_token(
        app=test_app,
        identity="oceana-user",
        roles=[]
    )

    response = test_app.test_client().get("/v1/free_pass", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}


def test_default_token_verification_admin(test_app):

    # Check token response for "admin" role
    token = generate_test_token(
        app=test_app,
        identity="oceana-admin",
        roles=["admin"]
    )

    response = test_app.test_client().get("/v1/admin", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}


def test_token_verification_function(test_app: Flask):

    with test_app.test_request_context():
        # Get extension
        jwt = get_jwt_extension()

        # Sets the callback function used for custom verification of a valid JWT.
        @jwt.set_token_verification_function
        def token_verification(_endpoint_id,
                               jwt_header,
                               _jwt_data,
                               optional,
                               allowed,
                               roles):
            """
            Token verification argument order is:
            endpoint_id, jwt_header, jwt_data, optional, allowed, roles.
            Also can be defined in a dynamic way:
            def token_verification(*args):
            """

            if len(jwt_header) == 0:
                raise ClientBadRequestException("JWT header is not present")

            if not optional:
                # Authorization for "reader" role granted
                allow = is_authorized(roles=roles, allowed=allowed)
                if not allow:
                    authorized = False
                    for r in roles:
                        if r == "custom-reader-access":
                            authorized = True
                            break

                    if not authorized:
                        raise ClientAuthenticationError("Authorization required")

    # Check token format response error
    response = test_app.test_client().get("/v1/optional", headers={
        "Authorization": "whatever"
    })
    assert response.status_code == int(HTTPStatus.BAD_REQUEST.value)
    assert response.get_json()["error"] == \
        "Bearer error=\"invalid_request\" error_description=\"JWT header is not present\""

    # Check token response
    token = generate_test_token(
        app=test_app,
        identity="oceana-user",
        roles=["role-cant-access"]
    )

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.UNAUTHORIZED.value)
    assert response.get_json()["error"] == \
        "Bearer error=\"invalid_token\" error_description=\"Authorization required\""

    # Check token response for custom role
    token = generate_test_token(
        app=test_app,
        identity="oceana-user",
        roles=["custom-reader-access"]
    )

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}

    # Check token response for "reader" role
    token = generate_test_token(
        app=test_app,
        identity="oceana-reader",
        roles=["reader"]
    )

    response = test_app.test_client().get("/v1/test", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}


def test_user_claims_function(test_app: Flask):

    with test_app.test_request_context():
        # Get extension
        jwt = get_jwt_extension()

        # Sets the callback function used for user claims of a valid JWT.
        @jwt.set_user_claims_function
        def user_claims(_identity):
            # This claim will be added in all tokens created
            return {
                "custom-claim": "my-custom-claim"
            }

        token, payload = create_access_token(
            identity="client_id",
            roles=["reader", "writer"],
            additional_claims={"custom-claim2": "my-custom-claim2"}
        )

        assert payload["custom-claim"] == "my-custom-claim"
        assert payload["custom-claim2"] == "my-custom-claim2"

        jwt_data, _jwt_header = jwt._decode_jwt_from_config(token=token)
        assert jwt_data["custom-claim"] == "my-custom-claim"
        assert jwt_data["custom-claim2"] == "my-custom-claim2"


def test_token_header_function(test_app: Flask):

    with test_app.test_request_context():
        # Get extension
        jwt = get_jwt_extension()

        # Sets the callback function used for user claims of a valid JWT.
        @jwt.set_token_header_function
        def token_header(_headers):
            # This property will be added in all token headers created
            return {
                "custom-header": "my-custom-header"
            }

        token, _payload = create_access_token(
            identity="client_id",
            roles=["reader", "writer"],
            additional_headers={"custom-header2": "my-custom-header2"}
        )

        _jwt_data, jwt_header = jwt._decode_jwt_from_config(token=token)
        assert jwt_header["custom-header"] == "my-custom-header"
        assert jwt_header["custom-header2"] == "my-custom-header2"
