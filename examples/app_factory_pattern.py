from flask import Blueprint, jsonify
from flask_restx import Namespace, Resource, Api
from _mock_auth_data import populate_auth_data

from oceana_jwt_auth import JWTExtension, auth_guard, info


# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")


@ns_test.route("/reader", methods=["GET"])
class TestReader(Resource):
    @auth_guard(secured=True)
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


# App is not available globally (Application Factory pattern)
# Create authorization extension
jwt = JWTExtension()

# Create flask app automatically from Api object
app = jwt.init_app(api=api)

# Register blueprint afterwards
app.register_blueprint(bp)

# Populate data to test
populate_auth_data(app)

if __name__ == "__main__":
    app.run()
