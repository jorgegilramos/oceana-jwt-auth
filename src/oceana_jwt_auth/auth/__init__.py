from flask import request
from flask_restx import Namespace, Resource, Api

from ..config import OCEANA_API_PROVIDER, OCEANA_API_AUTH_VERSION
from ..utils import info
from ..utils.constants import RestMethod, API_AUTH_DESCRIPTION
from ..api.common import response_api_ok, handle_exceptions
from ..auth_provider import authenticate
from ..jwt_handler import create_access_token

# Models and documents for swagger
from .models import bearer_token_model
from .docs import token_doc

from ..exceptions import ClientBadRequestException

authorizations = {
    "JWT": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization"
    }
    # https://swagger.io/docs/specification/v3_0/authentication/oauth2/
    # "entraid": {
    #     "type": "oauth2",
    #     "flow": "accessCode",
    #     "tokenUrl": "https://somewhere.com/token",
    #     "authorizationUrl": "https://somewhere.com/auth",
    #     "scopes": {
    #         "read": "Grant read-only access",
    #         "write": "Grant read-write access",
    #     }
    # }
}

security = "JWT"  # ["JWT", {"entraid": "read"}]


def default_authentication(client_id, client_secret):

    identity = {}
    if not client_id or not client_secret:
        raise ClientBadRequestException("Client id or client secret missing")

    identity = authenticate(provider=OCEANA_API_PROVIDER,
                            client_id=client_id,
                            client_secret=client_secret)
    return identity


def register_auth_namespace(api: Api):

    # Create auth namespace
    ns_auth = Namespace(
        name="Auth",
        description=f"{API_AUTH_DESCRIPTION}",
        path=f"/{OCEANA_API_AUTH_VERSION}/auth" if OCEANA_API_AUTH_VERSION else "/auth")
    # Register model
    ns_auth.model(name="Token", model=bearer_token_model)

    # Add authorization namespace
    api.add_namespace(ns_auth)

    @ns_auth.route("/token", methods=[RestMethod.POST.value])
    @ns_auth.doc(**token_doc)
    class GetToken(Resource):
        @handle_exceptions(endpoint="GetToken.post")
        def post(self):
            endpoint = "GetToken.post"
            info(f"Starting {endpoint} endpoint call ...")

            client_id = request.json.get("client_id")
            client_secret = request.json.get("client_secret")

            identity = default_authentication(client_id=client_id, client_secret=client_secret)

            client_id = identity["client_id"]
            roles = identity["roles"]

            info(f"{endpoint} - client_id: {client_id} - roles: {roles}")

            # Payload that the server will send back the client encoded in the JWT Token.
            # While generating a token, you can define any type of payload in valid JSON format
            # the iss(issuer), sub(subject) and aud(audience) are reserved claims.
            # https://tools.ietf.org/html/rfc7519#section-4.1
            # These reserved claims are not mandatory to define in a standard JWT token.

            token, payload = create_access_token(
                identity=client_id,
                roles=roles,
                expires_delta=None,
                additional_claims=None,
                additional_headers=None,
                payload={}
            )

            # Add token to return
            data = {
                "token": f"{token}"
            }

            # Added label "expiresIn" so applications can request for new tokens before
            # the token expiration time without the need to decode the JWT or receive an
            # https error from the authorization server.
            expires_in = payload.get("expires_in")
            if expires_in is not None:
                data = {**data, "expiresIn": expires_in}

            # Return token
            return response_api_ok(http_code=200, data=data, endpoint=None)
