import sys
from flask import Flask, Blueprint, jsonify, request
from flask_restx import Namespace, Resource, Api
from flask_restx import fields, Model

sys.path.insert(0, "./")
sys.path.insert(0, "./src")

# Package imports
from oceana_jwt_auth import JWTExtension, ConfigSqlite, ConfigPostgres, auth_guard, get_jwt, \
    get_identity, info, debug   # noqa: E402,F401
from oceana_jwt_auth import create_access_token, authenticate, OCEANA_API_PROVIDER, \
    handle_exceptions    # noqa: E402,F401
from oceana_jwt_auth.crypto_rsa import generate_rsa, \
    decode_rsa_private, decode_rsa_public    # noqa: E402,F401


# To execute inline
# from oceana_jwt_auth.jwt_extension import JWTExtension
# from  oceana_jwt_auth.auth_guard import auth_guard, get_jwt


# Linux create private key:
# openssl genrsa -out rsa_private_key.pem 2048
# Create public key:
# openssl rsa -pubout -in {path_private_pem} -out (path_public_pub)
# openssl rsa -pubout -in rsa_private_key.pem -out rsa_public_key.pub
# RSA_PRIVATE_KEY = """
# -----BEGIN PRIVATE KEY-----
# MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFyGYSBZAGDolR
# q8eUzPxwbY1oxbR8lC/FSH5wXKq4gxO8tJDmd4iI6hedCT+r7hg6KUccgaxwDcCl
# 3Q2aQc7U+XpTjyNlRaBzTztd/d6BqGrWxp8SV6qA+P1drLjcojOov37UA26w5T5N
# HOGc7Q/45zB7lEWuEQ9aISH/BoWKhcHvaOS41PfngGfO2PGb9zJXFnT8HgY4VDQD
# BFR8sCrQgYNiSKImI1OqaFoQMtwPklyERSQYSZEoY5cA55DJpBdxzLbo1RmV0hXD
# JvYMZ+1nwd2N4p2sKMUMmR9UA/brBMupM5ab9IJYQTv7NtJrjLoz0KvmCplOzRtF
# voNgS+HjAgMBAAECggEADQ3IetkGI/gypQLO9em/oZYBdtBRtMU9D+rUeYsMM4hn
# NZW/WI68Irk8nL8/BhR9Yd1WlbGTVYP62pen7a35PkJHChvQ7L63M9UfaHk4hds9
# TfanChliJggJBPVA8EL+YN1evBSL6j3/KizFUUuuObHcl9N18+KpXjwAl+nwx28l
# 3Jv6Luqx/8OG1mLfsjSxOjGueef59jEmFHDR8DCXuftRQl1P23X3mjY4EtYhXMH8
# pTiPb6zoTaxnDDt0lpUxRC6hsh/9V5enoxloJ/GAMX8NaDKsT/KFHGkH9xvBkOHF
# wLocJ+xuFu1FlqdtiQAkhfyJcvl6A9+7RdNO9z8t2QKBgQDWkhf1sXQiZAbYfbar
# rBdZJsJHfM+DD0W+lSApWN46IM7Jwu6zjSw2vfExv6l3FUZ5W8ezwqCq/LErTM08
# chapZWqTgPin793Z8g5nl19Bz/ENMZ+zi7WLf/Yt3AlwZABEEnYO+Mz4u1nDm+8b
# pwpZEQiGVaJJepnCj+k3/PUJaQKBgQDr+IGBojXmreh+e/h0c2rQ8HmK0zt2g7/R
# GY9lDQC64j0VMuR/fkEPPdqZYdX/CkFjTwGtCxjn6W2qXw4tg91WSx/UeAHhNH+o
# SS1u68bwPx0yS4Hx32q6fFKq6cazHUP/FMfVsuv/bUyGnD0USE0kYD2hb3JI8V0X
# kzSuhI/7awKBgGzvDqr1xHgRQEh4ylytqczhGJEilFd9UXNIUmOrcmcgcNuN05Hk
# giXomKMhIvAKJRVHu0NP9DHayDerbibZ5RdrHYh1WcgoxwD3GskM2JeY8lA4eVO2
# Ah0ogdsWctRUcK4ekUFYnvdIZnIgoGvxihddxm4s249iZt2YIlcCXYTBAoGBAI6t
# IVEKjWC/QlZICwAOUUWoQTUpZ0jPfImn1MYayJg29wv8S6Cy7A+VLLmVKFkfEE5F
# lRPWI+cFgyOCegYXNxtYLRTAwxIyNgXAyVHKCe11m+evNBDVL6k2Rp3E4DmotlZj
# cDjMCFnW8nBpw5yh4tLdxiX4RrfICKuafD4RNSWlAoGBAKizSy7eHApZ++MwpgLb
# WL5TMaeN2DS63zxVd50KmoG+j4FADFbid/mSmGihdQ71ggtHrneXpONA2QqXj00A
# 5iRzVOJx02I061beYmN/rsRI9ce3zBVkz1YchqwthRoKJvWtR1830nkMs0ZBYXit
# L+R7v1amgmZKtJH0LjlPM/eD
# -----END PRIVATE KEY-----
# """

# RSA_PUBLIC_KEY = """
# -----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxchmEgWQBg6JUavHlMz8
# cG2NaMW0fJQvxUh+cFyquIMTvLSQ5neIiOoXnQk/q+4YOilHHIGscA3Apd0NmkHO
# 1Pl6U48jZUWgc087Xf3egahq1safEleqgPj9Xay43KIzqL9+1ANusOU+TRzhnO0P
# +Ocwe5RFrhEPWiEh/waFioXB72jkuNT354Bnztjxm/cyVxZ0/B4GOFQ0AwRUfLAq
# 0IGDYkiiJiNTqmhaEDLcD5JchEUkGEmRKGOXAOeQyaQXccy26NUZldIVwyb2DGft
# Z8HdjeKdrCjFDJkfVAP26wTLqTOWm/SCWEE7+zbSa4y6M9Cr5gqZTs0bRb6DYEvh
# 4wIDAQAB
# -----END PUBLIC KEY-----
# """

RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = generate_rsa(bits=2048)

private_decoded = decode_rsa_private(RSA_PRIVATE_KEY, pem_format=False)
info(f"\nprivate_decoded:\n{private_decoded}")

public_decoded = decode_rsa_public(RSA_PUBLIC_KEY, pem_format=False)
info(f"\npublic_decoded:\n{public_decoded}")


app = Flask(__name__)

# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")

bearer_token_model = Model("Token", {
    "token": fields.String(
        description="Bearer token",
        pattern="Bearer [a-zA-Z_\\d]{100}"),
    "expiresIn": fields.String(
        description="Token expiration date"
    )
})

# Register model
ns_test.model(name="Token", model=bearer_token_model)


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
        200: ("Created OK", bearer_token_model),
        400: "Error",
        401: "Unauthorized",
        403: "Forbidden",
        500: "Internal Server Error"
    }
}


@ns_test.route("/login", methods=["POST"])
@ns_test.doc(**token_doc)
class GetLogin(Resource):
    @handle_exceptions()
    def post(self):
        endpoint = "Login"
        info(f"Starting {endpoint} endpoint call ...")

        client_id = request.json.get("client_id")
        client_secret = request.json.get("client_secret")

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


@ns_test.route("/test", methods=["GET"])
class TestApp(Resource):
    @auth_guard(secured=True)
    # @oceana_jwt_auth.auth_guard(secured=True)
    def get(self):
        oceana_jwt = get_jwt()
        roles = oceana_jwt.get("roles")
        client_id = get_identity()
        info(f"Get endpoint reached. Client_id: \"{client_id}\", Roles:{roles}")
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
    title="API JWT tokens",
    version="1.0",
    description="API JWT tokens",
)


# Add namespace
api.add_namespace(ns_test)

# Register blueprint
app.register_blueprint(bp)

app.config["JWT_ALGORITHM"] = "RS256"
app.config["JWT_SECRET_KEY"] = "secret_key"
app.config["RSA_PRIVATE_KEY"] = RSA_PRIVATE_KEY
app.config["RSA_PUBLIC_KEY"] = RSA_PUBLIC_KEY

# Add authentication extension
# oceana_jwt_auth.JWTExtension(app=app, api=api)
# JWTExtension(app=app, api=api, config_object=ConfigPostgres)
JWTExtension(app=app, api=api, config_object=ConfigSqlite)

# populate_auth_data(app)

# Populate to test in case no persistent database is used
if len(app.config["endpoint_security"]) == 0:
    with app.app_context():
        from oceana_jwt_auth.mock_auth_data import populate_endpoint_security_data, \
            populate_identity_data

        # Populate endpoint security and identities into the database
        populate_endpoint_security_data()
        populate_identity_data()

        from oceana_jwt_auth.database.auth_repository import get_endpoint_security_dict

        # Get endpoint security from database
        app.config["endpoint_security"] = get_endpoint_security_dict(provider=OCEANA_API_PROVIDER)
        # info(f"Endpoint security: {app.config["endpoint_security"]}")
        secured_endpoints = app.config["endpoint_security"]
        info(f"Secured endpoints: {len(secured_endpoints)}")
        for endpoint_id in secured_endpoints:
            roles = secured_endpoints[endpoint_id].get("roles")
            info(f"    - {endpoint_id}: {roles}")
        debug(f"Endpoint security: {secured_endpoints}")


if __name__ == "__main__":
    app.run()
