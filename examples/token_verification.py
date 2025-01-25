from flask import Flask, Blueprint, jsonify
from flask_restx import Namespace, Resource, Api

from _mock_auth_data import populate_auth_data
from oceana_jwt_auth import JWTExtension, ConfigSqlite, auth_guard, info


# App is available globally
app = Flask(__name__)
app.config["REGISTER_AUTH"] = True

# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")


@ns_test.route("/override_admin", methods=["GET"])
class TestAppAdminOverride(Resource):
    # Only admin role can access to the endpoint, this behaviour
    # will be changed in custom verification function
    @auth_guard(secured=True)
    def get(self):
        info("Get endpoint reached")
        return jsonify({"status": "OK", "code": 200})


@ns_test.route("/admin", methods=["GET"])
class TestAdmin(Resource):
    # Only admin role can access to the endpoint, this behaviour
    # can't be changed in custom verification function
    @auth_guard(admin=True)
    def get(self):
        info("Get endpoint reached")
        return jsonify({"status": "OK", "code": 200})


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


# Sets the callback function used for custom verification of a valid JWT.
@jwt.set_token_verification_function
def token_verification(endpoint_id,
                       jwt_header,
                       jwt_data,
                       optional,
                       allowed,
                       roles):
    """
    Token verification argument order is:
    endpoint_id, jwt_header, jwt_data, optional, allowed, roles.
    Also can be defined in a dynamic way:
    def token_verification(*args):
    """
    # Allow all roles, but with a valid token
    return True, None


# Populate data to test
populate_auth_data(app)

if __name__ == "__main__":
    app.run()
