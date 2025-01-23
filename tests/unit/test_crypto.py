import pytest
from flask import Flask
from http import HTTPStatus

from cryptography.hazmat.primitives.asymmetric.rsa import \
    RSAPrivateKeyWithSerialization as RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import \
    RSAPublicKeyWithSerialization as RSAPublicKey

from oceana_jwt_auth import info, OCEANA_API_PROVIDER, create_access_token
from oceana_jwt_auth.crypto_rsa import generate_rsa, decode_rsa_private, \
    decode_rsa_public, encode_private_key, encode_public_key
from oceana_jwt_auth.internals import get_jwt_extension


# Create keys to test
RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = generate_rsa(bits=2048)

# PEM format
private_decoded_pem = decode_rsa_private(RSA_PRIVATE_KEY, pem_format=True)
info(f"\nprivate_decoded_pem:\n{private_decoded_pem}")

public_decoded_pem = decode_rsa_public(RSA_PUBLIC_KEY, pem_format=True)
info(f"\npublic_decoded_pem:\n{public_decoded_pem}")


def test_token_errors(test_app: Flask):

    with test_app.test_request_context():
        # Change encryption algorithm to RS256
        test_app.config["TOKEN_ALGORITHM"] = "RS256"
        # Validate exception
        with pytest.raises(RuntimeError) as exc_info:
            _token_rs256, _payload_rs256 = create_access_token(
                identity="client_id",
                roles=["reader", "writer"]
            )
        assert str(exc_info.value) == "Can't encode without private key"

        # Add private key
        # Test with PEM string key
        test_app.config["RSA_PRIVATE_KEY"] = private_decoded_pem
        token_rs256, _payload_rs256 = create_access_token(
            identity="client_id",
            roles=["reader", "writer"]
        )
        assert token_rs256 is not None and isinstance(token_rs256, str)

        # Test with object RSAPrivateKey
        test_app.config["RSA_PRIVATE_KEY"] = RSA_PRIVATE_KEY
        token_rs256, _payload_rs256 = create_access_token(
            identity="client_id",
            roles=["reader", "writer"]
        )
        assert token_rs256 is not None and isinstance(token_rs256, str)

        # Get extension
        jwt_extension = get_jwt_extension()
        with pytest.raises(RuntimeError) as exc_info:
            _jwt_data, _jwt_header = jwt_extension._decode_jwt_from_config(token=token_rs256)
        assert str(exc_info.value) == "Can't decode without public key"

        # Test with PEM public string key
        test_app.config["RSA_PUBLIC_KEY"] = public_decoded_pem
        jwt_data, jwt_header = jwt_extension._decode_jwt_from_config(token=token_rs256)
        assert jwt_header == {"alg": "RS256", "typ": "JWT"}
        assert jwt_data is not None and \
            jwt_data["type"] == "access" and \
            jwt_data["sub"] == "client_id" and \
            jwt_data["roles"] == ["reader", "writer"] and \
            jwt_data["iss"] == OCEANA_API_PROVIDER and \
            jwt_data["version"] == "v1"

        # Test with RSAPublicKey
        test_app.config["RSA_PUBLIC_KEY"] = RSA_PUBLIC_KEY
        jwt_data, jwt_header = jwt_extension._decode_jwt_from_config(token=token_rs256)
        assert jwt_header == {"alg": "RS256", "typ": "JWT"}
        assert jwt_data is not None and \
            jwt_data["type"] == "access" and \
            jwt_data["sub"] == "client_id" and \
            jwt_data["roles"] == ["reader", "writer"] and \
            jwt_data["iss"] == OCEANA_API_PROVIDER and \
            jwt_data["version"] == "v1"


def test_crypto_rsa(test_app: Flask):

    with test_app.test_request_context():
        # Create HS256 token as default algorithm
        token_hs256, _payload_hs256 = create_access_token(
            identity="client_id",
            roles=["reader", "writer"]
        )

        # Change encryption algorithm to RS256
        test_app.config["TOKEN_ALGORITHM"] = "RS256"
        test_app.config["RSA_PUBLIC_KEY"] = RSA_PUBLIC_KEY
        test_app.config["RSA_PRIVATE_KEY"] = RSA_PRIVATE_KEY
        token_rs256, _payload_rs256 = create_access_token(
            identity="client_id",
            roles=["reader", "writer"]
        )

    # Now HS256 token must fail now
    url = "/v1/test"
    bearer_header = {"Authorization": f"Bearer {token_hs256}"}
    response = test_app.test_client().get(url, headers=bearer_header)
    assert response.status_code == int(HTTPStatus.UNAUTHORIZED.value)
    assert response.get_json()["error"] == \
        "Bearer error=\"invalid_token\" " + \
        "error_description=\"Invalid access token: The specified alg value is not allowed\""

    # But RSA256 token must work
    bearer_header = {"Authorization": f"Bearer {token_rs256}"}
    response = test_app.test_client().get(url, headers=bearer_header)
    assert response.status_code == int(HTTPStatus.OK.value)
    assert response.get_json() == {"status": "OK", "code": 200}


def test_decode_rsa_der_keys():

    # DER format
    private_decoded_der = decode_rsa_private(RSA_PRIVATE_KEY, pem_format=False)
    assert isinstance(private_decoded_der, str)
    info(f"\nprivate_decoded_der:\n{private_decoded_der}")

    public_decoded_der = decode_rsa_public(RSA_PUBLIC_KEY, pem_format=False)
    assert isinstance(public_decoded_der, str)
    info(f"\npublic_decoded_der:\n{public_decoded_der}")


def test_decode_rsa_pem_keys():
    # PEM format
    # private_decoded_pem = decode_rsa_private(RSA_PRIVATE_KEY, pem_format=True)
    assert isinstance(private_decoded_pem, str)
    info(f"\nprivate_decoded_pem:\n{private_decoded_pem}")

    # public_decoded_pem = decode_rsa_public(RSA_PUBLIC_KEY, pem_format=True)
    assert isinstance(public_decoded_pem, str)
    info(f"\npublic_decoded_pem:\n{public_decoded_pem}")


def test_encode_private_key():
    private_decoded_der = decode_rsa_private(RSA_PRIVATE_KEY, pem_format=False)
    rsa_private_key = encode_private_key(data=private_decoded_der)

    assert isinstance(rsa_private_key, RSAPrivateKey)


def test_encode_public_key():
    public_decoded_der = decode_rsa_public(RSA_PUBLIC_KEY, pem_format=False)
    rsa_public_key = encode_public_key(data=public_decoded_der)

    assert isinstance(rsa_public_key, RSAPublicKey)
