import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import \
    RSAPrivateKeyWithSerialization as RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import \
    RSAPublicKeyWithSerialization as RSAPublicKey
from cryptography.hazmat.backends import default_backend

from collections import namedtuple

RSAKeyTuple = namedtuple("RSAKeyTuple", ("private", "public"))


def generate_rsa(bits: int = 2048) -> RSAKeyTuple:
    """
    Generate an RSA tuple in PEM format
    :param bits:
        Number of bits to create the key
    :return:
        Private key and public key
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )

    public_key = private_key.public_key()

    return RSAKeyTuple(private=private_key, public=public_key)


def decode_rsa_private(private_key: RSAPrivateKey, pem_format=True) -> str:
    if pem_format:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            encryption_algorithm=serialization.NoEncryption(),
            format=serialization.PrivateFormat.PKCS8
        ).decode()
    else:
        return base64.b64encode(
            private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                encryption_algorithm=serialization.NoEncryption(),
                format=serialization.PrivateFormat.PKCS8
            )
        ).decode()


def decode_rsa_public(public_key: RSAPublicKey, pem_format=True) -> str:
    if pem_format:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        ).decode()
    else:
        return base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.PKCS1
            )
        ).decode()


def encode_private_key(data: str) -> RSAPrivateKey:
    return serialization.load_der_private_key(
        data=base64.b64decode(data),
        password=None,
        backend=default_backend()
    )


def encode_public_key(data: str) -> RSAPublicKey:
    return serialization.load_der_public_key(
        data=base64.b64decode(data),
        backend=default_backend()
    )
