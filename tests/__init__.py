import jwt
from flask import Flask
from typing import Tuple, List, Dict


from oceana_jwt_auth.config import OCEANA_API_SECRET_KEY
from oceana_jwt_auth.jwt_handler import create_access_token


# Api header with token for all requests
# oceana_api_auth_header = """{{
#     "Content-Type": "application/json",
#     "Accept": "application/json",
#     "Authorization": "{token}"
# }}"""


# payload = {
#     "client_id": "oceana-api-client1",
#     "roles": ["reader", "writer"]
# }
# token = f"Bearer {generate_jwt(payload=payload)}"
# headers = json.loads(oceana_api_auth_header.format(token=token))


def generate_test_token(
        app: Flask,
        identity: str,
        roles: List[str],
        payload: Dict = {}) -> Tuple[str, Dict]:
    with app.app_context():
        token, _ = create_access_token(
            identity=identity,
            roles=roles,
            expires_delta=None,
            additional_claims=None,
            additional_headers=None,
            payload=payload
        )
    return token


def mock_test_token_payload(
        identity: str,
        roles: List[str],
        payload: Dict = {}) -> str:
    # payload["sub"] = identity
    payload["roles"] = roles
    return jwt.encode(payload, OCEANA_API_SECRET_KEY, algorithm="HS256")
