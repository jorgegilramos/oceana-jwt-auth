import pytest
from flask import Flask

from oceana_jwt_auth import create_access_token, OCEANA_API_PROVIDER
from oceana_jwt_auth.internals import get_jwt_extension
from oceana_jwt_auth.exceptions import ClientAuthenticationError, \
    ClientJWTDecodeException

from .. import mock_test_token_payload


def test_audience(test_app: Flask):

    with test_app.test_request_context():

        test_app.config["JWT_ENCODE_AUDIENCE"] = "my-audience"
        token, payload = create_access_token(
            identity="oceana-reader",
            roles=["reader"],
            additional_claims=None,
            additional_headers=None
        )
        assert payload["aud"] == "my-audience"

        # Get extension and decode token
        jwt_extension = get_jwt_extension()
        jwt_data, jwt_header = jwt_extension._decode_jwt_from_config(token=token)
        assert jwt_header["alg"] == "HS256" and jwt_header["typ"] == "JWT"
        assert jwt_data["aud"] == "my-audience"

        test_app.config["JWT_DECODE_AUDIENCE"] = "not-my-audience"
        with pytest.raises(ClientAuthenticationError) as exc_info:
            jwt_extension._decode_jwt_from_config(token=token)
        assert str(exc_info.value) == "Invalid access token: Audience doesn't match"


def test_decode_jwt_identity_claim(test_app: Flask):

    with test_app.test_request_context():

        token = mock_test_token_payload(
            identity="oceana-reader",
            roles=["reader"],
            payload={"iss": OCEANA_API_PROVIDER}
        )

        jwt_extension = get_jwt_extension()
        with pytest.raises(ClientJWTDecodeException) as exc_info:
            jwt_extension._decode_jwt_from_config(token=token)
        assert str(exc_info.value) == "Invalid access token: Missing claim: sub"


def test_decode_jwt_version_claim(test_app: Flask):

    with test_app.test_request_context():

        jwt_extension = get_jwt_extension()

        token = mock_test_token_payload(
            identity="oceana-reader",
            roles=["reader"],
            payload={"iss": OCEANA_API_PROVIDER, "sub": "client_id"}
        )

        with pytest.raises(ClientJWTDecodeException) as exc_info:
            jwt_extension._decode_jwt_from_config(token=token)
        assert str(exc_info.value) == "Invalid access token: Missing claim: version"

        token = mock_test_token_payload(
            identity="oceana-reader",
            roles=["reader"],
            payload={
                "iss": OCEANA_API_PROVIDER,
                "sub": "client_id",
                "version": "v2"
                }
        )
        with pytest.raises(ClientJWTDecodeException) as exc_info:
            jwt_extension._decode_jwt_from_config(token=token)
        assert str(exc_info.value) == "Invalid access token: Token version doesn't match"


def test_decode_jwt_default_properties(test_app: Flask):

    with test_app.test_request_context():

        jwt_extension = get_jwt_extension()

        token = mock_test_token_payload(
            identity="oceana-reader",
            roles=["reader"],
            payload={"iss": OCEANA_API_PROVIDER, "sub": "client_id", "version": "v1"}
        )

        jwt_data, jwt_header = jwt_extension._decode_jwt_from_config(token=token)
        assert jwt_header["alg"] == "HS256" and jwt_header["typ"] == "JWT"
        assert jwt_data["type"] == "access"
        assert jwt_data["jti"] is None
