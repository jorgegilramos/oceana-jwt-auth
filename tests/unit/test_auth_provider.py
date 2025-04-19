import pytest
from flask import Flask

from oceana_jwt_auth import authenticate, OCEANA_API_PROVIDER
from oceana_jwt_auth.utils import generate_key, generate_salt
from oceana_jwt_auth.auth import default_authentication
from oceana_jwt_auth.exceptions import ClientAuthenticationError, \
    ClientBadRequestException


def test_generate_key():

    key = generate_key()
    assert isinstance(key, bytes)


def test_generate_salt():

    salt = generate_salt()
    assert isinstance(salt, str)


def test_authentication_ok(test_app: Flask):

    with test_app.test_request_context():
        user_data = authenticate(provider=OCEANA_API_PROVIDER,
                                 client_id="oceana-reader",
                                 client_secret="bad_password")
    assert user_data["client_id"] == "oceana-reader" and \
        user_data["client_type"] == "application" and \
        user_data["roles"] == ["reader"]


def test_invalid_user_error(test_app: Flask):

    with test_app.test_request_context():
        with pytest.raises(ClientAuthenticationError) as exc_info:
            authenticate(provider=OCEANA_API_PROVIDER,
                         client_id="not-my-user",
                         client_secret="not-my-password")

    assert str(exc_info.value) == \
        "Invalid credentials for client id: \"not-my-user\""


def test_invalid_password_error(test_app: Flask):

    with test_app.test_request_context():
        with pytest.raises(ClientAuthenticationError) as exc_info:
            authenticate(provider=OCEANA_API_PROVIDER,
                         client_id="oceana-reader",
                         client_secret="not-my-password")

    assert str(exc_info.value) == \
        "Invalid credentials for client id: \"oceana-reader\""


def test_default_authentication_error(test_app: Flask):

    with pytest.raises(ClientBadRequestException) as exc_info:
        default_authentication(client_id="", client_secret="")

    assert str(exc_info.value) == \
        "Client id or client secret missing"
