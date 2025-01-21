from flask import Flask, Blueprint, jsonify
from flask_restx import Namespace, Resource, Api
from functools import wraps
from datetime import datetime
from _mock_auth_data import populate_auth_data


from oceana_jwt_auth import JWTExtension, ConfigSqlite, info, \
    handle_exceptions, verify_jwt
from oceana_jwt_auth.exceptions import ClientAuthenticationError

# App is available globally
app = Flask(__name__)
app.config["REGISTER_AUTH"] = True

# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")


def required_last_minutes(minutes=10):
    def wrapper(route_function):
        @wraps(route_function)
        def decorated_function(*args, **kwargs):
            # Verify jwt
            jwt_data, jwt_header = verify_jwt(optional=False)
            # Get roles from jwt
            iat = jwt_data.get("iat")
            iat_dt = datetime.fromtimestamp(iat)
            created = jwt_data.get("created")

            info(f"Token created time: {created}")
            now = datetime.now()
            if (now - iat_dt).total_seconds() < int(minutes)*60:
                return route_function(*args, **kwargs)
            else:
                raise ClientAuthenticationError(f"Invalid JWT: created before {minutes} minutes")
        return decorated_function
    return wrapper


@ns_test.route("/minutes", methods=["GET"])
class TestApp(Resource):
    @handle_exceptions()
    @required_last_minutes(minutes=2)
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


# Populate data to test
populate_auth_data(app)

if __name__ == "__main__":
    app.run()
