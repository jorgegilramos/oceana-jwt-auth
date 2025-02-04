# oceana_jwt_auth

![Build Status](https://github.com/jorgegilramos/oceana-jwt-auth/workflows/Python%20package/badge.svg)
[![PyPI version](https://badge.fury.io/py/oceana-jwt-auth.svg)](https://badge.fury.io/py/oceana-jwt-auth)
![PyPI - Downloads](https://img.shields.io/pypi/dm/oceana-jwt-auth)

Oceana API library to add authorization in Flask Restx applications using JWT tokens.

## Setup

Install latest version
```shell
pip install oceana_jwt_auth
```

## Usage

Code is provided in examples directory.

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

app[SQLALCHEMY_DATABASE_URI] = "postgresql://postgres:postgres@127.0.0.1:5432/oceana_jwt_auth"


JWTExtension(app=app, api=api, config_object=ConfigPostgres)

```
Connection string can be stored in environment parameters:
```bash
# Connection configuration
SQLALCHEMY_DATABASE_URI="postgresql://postgres:postgres@127.0.0.1:5432/oceana_jwt_auth"
```
or:
```bash
# Connection configuration
DB_HOST=127.0.0.1
DB_NAME=oceana_jwt_auth
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_PORT=5432
DB_SCHEMA=public
DB_CREATE_ENTITIES=true
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
pip install --upgrade --no-deps --force-reinstall dist\oceana_jwt_auth-0.0.5-py3-none-any.whl
```

```shell
# Reinstall with dependencies
pip install dist\oceana_jwt_auth-0.0.5-py3-none-any.whl --force-reinstall
```

Check style guide enforcement
```shell
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
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

| Library                | Version |
|------------------------|---------|
| build                  | 1.2.1   |
| setuptools             | 67.8.0  |
| wheel                  | 0.38.4  |
| requests               | 2.29.0  |
| flake8                 | 4.0.1   |
| python-decouple        | 3.8     |
| flask                  | 3.1.0   |
| flask-restx            | 1.3.0   |
| typing-extensions      | 4.12.2  |
| pyjwt                  | 2.8.0   |
| SQLAlchemy             | 2.0.36  |
| Flask-SQLAlchemy       | 3.1.1   |
| cryptography           | 41.0.7  |


# Tests requirements
| Library                | Version |
|------------------------|---------|
| requests-mock          | 1.21.1  |
| pytest                 | 7.4.0   |
| pytest-env             | 1.1.5   |
| coverage               | 6.4.4   |
| flake8                 | 4.0.1   |
| tox                    | 4.23.2  |


# Postgres
| Library                | Version |
|------------------------|---------|
| psycopg2               | 2.9.9   |


## Releases
**Version 0.0.5**:
   - First version