# oceana_jwt_auth

![Build Status](https://github.com/jorgegilramos/oceana-jwt-auth/workflows/Python%20package/badge.svg)
![Supported Python Versions](https://img.shields.io/pypi/pyversions/oceana_jwt_auth)
[![PyPI version](https://badge.fury.io/py/oceana-jwt-auth.svg)](https://badge.fury.io/py/oceana-jwt-auth)
![PyPI - Downloads](https://img.shields.io/pypi/dm/oceana-jwt-auth)

## Description

**oceana-jwt-auth** library is designed to be a drop-in solution for adding JWT-based authentication to Flask-RestX applications with minimal configuration while providing extensive customization options for complex security requirements.

## Main Features
**JWT Token Management**
- **Token Creation & Validation**: Generate and validate JWT tokens using multiple algorithms (HS256, HS384, HS512, ES256, RS256, etc.)
- **Flexible Token Configuration**: Configurable token expiration, issuer, audience, and algorithms
- **RSA Support**: Support for RSA public/private key encryption for enhanced security

**Flask-RestX Integration**
- **Native Integration**: Purpose-built for Flask-RestX applications with automatic API documentation
- **Swagger Documentation**: Automatic security documentation in Swagger UI with authorization support
- **Namespace Support**: Seamless integration with Flask-RestX namespaces and blueprints

**Authorization & Authentication**

- **Role-Based Access Control (RBAC)**: Support for user roles and permissions
- **Multi-level Security**:
  - `@auth_guard(secured=True)` - Basic authentication
  - `@auth_guard(admin=True)` - Admin-level access
  - Custom decorators for specific business logic
- Identity Management: Built-in user identity and endpoint security models

**Database Integration**
- **Multiple Database Support**:
  - SQLite (for development/testing)
  - PostgreSQL (for production)
  - Configurable via environment variables or connection strings
- **Automatic Schema Management**: Auto-creation of security tables (`sec_identity`, `sec_endpoint`)
- SQLAlchemy Integration: Built on Flask-SQLAlchemy for robust ORM support

**Configuration Management**
- **Environment-Based Configuration**: Comprehensive environment variable support
- **Multiple Configuration Classes**: Pre-built configurations for different deployment scenarios
- **Flexible Setup**: Support for both direct instantiation and application factory patterns

**Security Features**
- **Cryptographic Utilities**: Built-in password hashing, salt generation, and secure string comparison
- **Token Verification**: Configurable token verification with custom callbacks
- **Exception Handling**: Comprehensive error handling with custom exception types
- **Request Validation**: Automatic validation of authorization headers and token format

**Production Ready**
- **Environment Variable Support**: Full 12-factor app compliance (to the [Twelve-Factor App methodology](https://12factor.net)
- **Database Connection Pooling**: Efficient database connection management
- **Token Refresh**: Support for refresh tokens with configurable expiration
- **Configurable Security**: Global and per-endpoint security configuration

**Developer Experience**
- **Logging Integration**: Built-in logging with configurable levels and handlers
- **Error Handling Decorators**: `@handle_exceptions()` decorator for consistent error responses
- **Mock Data Support**: Built-in tools for testing and development
- **Extensive Examples**: Complete usage examples for different scenarios

## Installation

Install latest version from PyPI:
```shell
pip install oceana_jwt_auth
```

## Usage

Code is provided in examples directory.

Easy Integration:
```python
# Simple setup
from oceana_jwt_auth import JWTExtension, auth_guard

jwt = JWTExtension(app=app, api=api)

@auth_guard(secured=True)
def protected_endpoint():
    return {"message": "Authorized access"}
```


Create Flask application and JWTExtension:
```python
from oceana_jwt_auth import JWTExtension, auth_guard, info

# App is available globally
app = Flask(__name__)

# Create namespace
ns_test = Namespace("Test", description="Test API", path="/v1")

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
```

Create a decorator (also in examples directory):
```python
from oceana_jwt_auth import JWTExtension, ConfigSqlite, info, \
    handle_exceptions, verify_jwt
from oceana_jwt_auth.exceptions import ClientAuthenticationError

# App is available globally
app = Flask(__name__)
# Settings can be set in app configuration 
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
    @required_last_minutes(minutes=2)  # User defined decorator
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
```

Config authorization witha a Postgres database:
```python
# Import Postgres configuration object
from oceana_jwt_auth import JWTExtension, ConfigPostgres

app[SQLALCHEMY_DATABASE_URI] = "postgresql://postgres:postgres@localhost:5432/oceana_jwt_auth"


JWTExtension(app=app, api=api, config_object=ConfigPostgres)

```
Connection string can be stored in environment parameters:
```bash
# Connection configuration
SQLALCHEMY_DATABASE_URI="postgresql://postgres:postgres@localhost:5432/oceana_jwt_auth"
```
or:
```bash
# Connection configuration
OCEANA_API_DB_AUTH_HOST=localhost
OCEANA_API_DB_AUTH_DATABASE=oceana_jwt_auth
OCEANA_API_DB_AUTH_USERNAME=postgres
OCEANA_API_DB_AUTH_PASSWORD=postgres
OCEANA_API_DB_AUTH_PORT=5432
OCEANA_API_DB_AUTH_SCHEMA=public
OCEANA_API_DB_AUTH_CREATE_ENTITIES=true
```


## Environment

Properties in environment variables:
```shell
# Database provider and issuer of JWT tokens
OCEANA_API_PROVIDER=OceanaAPI
# Security properties, it enables global security
OCEANA_API_SECURED=true
# Oceana API Secret key
OCEANA_API_SECRET_KEY=secret_key
# Generate a JWT with valid within 1 hour by now (in minutes)
OCEANA_API_TOKEN_MAX_MINUTES=60
```

## Packaging

Build package
```shell
# Using build package
python -m build
```


Run tests
```shell
# All tests
pytest -q -rP

# Partial tests
pytest tests/unit/test_application.py -v -rP
pytest tests/functional/test_validation.py -v -rP
pytest tests/unit/test_common.py -v -rP

# With coverage
coverage run -m pytest tests -v
coverage html
```


```shell
# Reinstall avoiding reinstalling dependencies
pip install --upgrade --no-deps --force-reinstall dist\oceana_jwt_auth-0.0.9-py3-none-any.whl
```

```shell
# Reinstall with dependencies
pip install dist\oceana_jwt_auth-0.0.9-py3-none-any.whl --force-reinstall
```

Check style guide enforcement
```shell
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=120 --statistics
```

Tox
```shell
# Command to test only one python version
tox -e py39
```


## Uninstall

```shell
pip uninstall oceana_jwt_auth
```


## Dependencies

| Library                | Version    |
|------------------------|------------|
| requests               | >= 2.29.0  |
| python-decouple        | == 3.8     |
| flask                  | >= 3.1.0   |
| flask-restx            | >= 1.3.0   |
| typing-extensions      | >= 4.12.2  |
| pyjwt                  | >= 2.8.0   |
| SQLAlchemy             | >= 2.0.36  |
| Flask-SQLAlchemy       | >= 3.1.1   |
| cryptography           | >= 41.0.7  |
| psycopg2               | >= 2.9.9   |


## Releases

**Version 0.0.9**:
   - Python upgraded ["3.9", "3.10", "3.11"] -> ["3.12", "3.13", "3.14"]
   - Upgrading libraries dependencies

**Version 0.0.8**:
   - First version