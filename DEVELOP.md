# oceana-jwt-auth

## Description

**oceana-jwt-auth** library is designed to support the [12-Factor app compliance](https://12factor.net), that refers to adherence to the Twelve-Factor App methodology, a set of best practices for building modern, scalable, maintainable software-as-a-service applications.


**Why This Matters for oceana-jwt-auth**

**Environment-Driven Configuration:** The library reads all critical settings from environment variables rather than hardcoded values, making it deployment-ready across different environments without code changes.

**Cloud-Native Ready:** You can deploy the same application code to development (SQLite), staging, and production (PostgreSQL) just by changing environment variables.

**Scalable Architecture:** JWT tokens are stateless, so multiple application instances can validate tokens independently without shared state.

**DevOps Friendly:** The library's configuration approach aligns with modern containerization and orchestration platforms (Docker, Kubernetes) that inject configuration via environment variables.

This compliance makes oceana-jwt-auth suitable for modern cloud deployments, microservices architectures, and continuous integration/deployment pipelines.


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
pytest tests/unit/test_auth_provider.py -v -rP
pytest tests/functional/test_validation.py -v -rP

# With coverage
coverage run -m pytest tests -v
coverage html
```


```shell
# Reinstall wheel avoiding reinstalling dependencies
pip install --no-deps --force-reinstall dist\oceana_jwt_auth-0.0.9-py3-none-any.whl
```

```shell
# Reinstall wheel with dependencies
pip install dist\oceana_jwt_auth-0.0.9-py3-none-any.whl --force-reinstall
```

```shell
# Install library from code
pip install -e .
```

Check style guide enforcement
```shell
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=120 --statistics
```

Tox
```shell
# Test only one python version
tox -e py312
# Test all python versions
tox
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

# Develop requirements

| Library                | Version    |
|------------------------|------------|
| build                  | >= 1.2.2   |
| setuptools             | >= 78.1.0  |
| wheel                  | >= 0.45.1  |
| requests-mock          | >= 1.21.1  |
| pytest                 | >= 8.3.5   |
| pytest-env             | >= 1.1.5   |
| coverage               | >= 7.8.0   |
| flake8                 | >= 7.2.0   |
| tox                    | >= 4.25.2  |



## Releases

**Version 0.0.9**:
   - Updated libraries versions

**Version 0.0.8**:
   - First version