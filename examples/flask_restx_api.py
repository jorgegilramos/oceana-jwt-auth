from flask import Flask, Blueprint, jsonify
from flask_restx import Namespace, Resource, Api
from _mock_auth_data import populate_auth_data

from oceana_jwt_auth import JWTExtension, auth_guard, info


# App is available globally
app = Flask(__name__)

# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")


@ns_test.route("/admin", methods=["GET"])
class TestApp(Resource):
    @auth_guard(admin=True)
    def get(self):
        info("Get endpoint reached")
        return jsonify({"status": "OK", "code": 200})


@ns_test.route("/reader", methods=["GET"])
class TestReader(Resource):
    @auth_guard(secured=True)
    def get(self):
        info("Get endpoint reached")
        return jsonify({"status": "OK", "code": 200})


@ns_test.route("/writer", methods=["GET"])
class TestWriter(Resource):
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

# Register blueprint
app.register_blueprint(bp)

# Create authorization extension from app and api objects
JWTExtension(app=app, api=api)


# Populate data to test
populate_auth_data(app)

if __name__ == "__main__":
    app.run()
