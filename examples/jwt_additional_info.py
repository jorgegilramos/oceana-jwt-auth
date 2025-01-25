from flask import Flask, Blueprint, jsonify, request
from flask_restx import Namespace, Resource, Api, fields, Model
from _mock_auth_data import populate_auth_data

from oceana_jwt_auth import JWTExtension, ConfigSqlite, auth_guard, info, \
    handle_exceptions, create_access_token, authenticate, OCEANA_API_PROVIDER, \
    get_jwt, get_identity


# App is available globally
app = Flask(__name__)
# Audience is now mandatory, only allow tokens created with our /login endpoint
app.config["TOKEN_DECODE_AUDIENCE"] = "audience_example"

# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")

token_model = Model("Token", {
    "token": fields.String(
        description="Bearer token",
        pattern="Bearer [a-zA-Z_\\d]{100}")
})

# Register model
ns_test.model(name="Token", model=token_model)

token_doc = {
    "params": {
        "body": {
            "description": "JSON data for the api",
            "in": "body",
            "type": "schema",
            "required": True,
            "schema": {
                "required": ["client_id", "client_secret"],
                "type": "object",
                "properties": {
                    "client_id": {"type": "string", "description": "Client identifier"},
                    "client_secret": {"type": "string", "description": "Client secret"}
                }
            }
        }
    },
    "description": "Authentication",
    "responses": {
        200: ("Created OK", token_model),
        400: "Error",
        401: "Unauthorized",
        403: "Forbidden",
        500: "Internal Server Error"
    }
}


@ns_test.route("/login", methods=["POST"])
@ns_test.doc(**token_doc)
class GetToken(Resource):
    # Decorator to handle authentication exceptions
    @handle_exceptions()
    def post(self):
        endpoint = "Login"
        info(f"Starting {endpoint} endpoint call ...")

        client_id = request.json.get("client_id")
        client_secret = request.json.get("client_secret")

        # Use your authentication method here if desired
        user_data = authenticate(provider=OCEANA_API_PROVIDER,
                                 client_id=client_id,
                                 client_secret=client_secret)

        client_id = user_data["client_id"]
        roles = user_data["roles"]

        info(f"{endpoint} - client_id: {client_id} - roles: {roles}")

        additional_claims = {"aud": "audience_example"}
        payload = {"information": "additional information"}

        token, payload = create_access_token(
            identity=client_id,
            roles=roles,
            expires_delta=None,
            additional_claims=additional_claims,
            additional_headers=None,
            payload=payload
        )

        return jsonify(token=f"{token}")


@ns_test.route("/admin", methods=["GET"])
class TestApp(Resource):
    # Only admin role can access to the endpoint
    @auth_guard(admin=True)
    def get(self):
        oceana_jwt = get_jwt()
        roles = oceana_jwt.get("roles")
        client_id = get_identity()

        additional_claims = oceana_jwt.get("aud")
        payload = oceana_jwt.get("information")
        info(f"Get endpoint reached. Client_id: \"{client_id}\", Roles:{roles}")
        info(f"Additional claims: \"{additional_claims}\"")
        info(f"Payload: \"{payload}\"")
        return jsonify({"status": "OK", "code": 200, "jwt": oceana_jwt})


@ns_test.route("/reader", methods=["GET"])
class TestReader(Resource):
    @auth_guard(secured=True)
    def get(self):
        info("Get endpoint reached")
        oceana_jwt = get_jwt()
        return jsonify({"status": "OK", "code": 200, "jwt": oceana_jwt})


@ns_test.route("/writer", methods=["GET"])
class TestWriter(Resource):
    @auth_guard(secured=True)
    def get(self):
        info("Get endpoint reached")
        oceana_jwt = get_jwt()
        return jsonify({"status": "OK", "code": 200, "jwt": oceana_jwt})


bp = Blueprint("test", __name__)
api = Api(
    app=bp,
    title="Test API",
    version="1.0",
    description="Test API",
)

# Add namespace
api.add_namespace(ns_test)

# Register blueprint
app.register_blueprint(bp)

# Create authorization extension from app and api objects
jwt = JWTExtension(app=app, api=api, config_object=ConfigSqlite)


# Populate data to test
populate_auth_data(app)

if __name__ == "__main__":
    app.run()
