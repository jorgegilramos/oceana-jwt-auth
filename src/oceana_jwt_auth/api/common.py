from flask import json, Response
from functools import wraps
from http import HTTPStatus
from typing import Callable

from ..utils.utils import error
from ..exceptions import HttpResponseError


def response_api_ok(http_code, data: dict, headers: dict = {}, endpoint: str = None) -> Response:

    data = {**data, "status": "OK", "code": http_code}
    if endpoint is not None:
        data["endpoint"] = endpoint
    response = Response(
        response=json.dumps(data),
        status=http_code,
        mimetype="application/json",
        headers=headers
    )
    return response


def response_api_error(http_code, error, headers: dict = {}, endpoint: str = None) -> Response:

    data = {"error": error, "status": "ERROR", "code": http_code}
    if endpoint is not None:
        data["endpoint"] = endpoint
    response = Response(
        response=json.dumps(data),
        status=http_code,
        mimetype="application/json",
        headers=headers
    )
    return response


def handle_exceptions(**kwargs) -> Callable:

    endpoint: str = kwargs.get("endpoint", None)

    def wrapper(route_function):

        @wraps(route_function)
        def decorated_function(*args, **kwargs):
            endpoint_id = route_function.__qualname__ if not endpoint else endpoint
            try:
                #
                # return current_app.ensure_sync(route_function)(*args, **kwargs)
                return route_function(*args, **kwargs)
            except HttpResponseError as e:
                error_msg = f"Bearer {e.error_description()}"
                error(f"{error_msg}")
                http_code = e.status_code
                headers = {"WWW-Authenticate": f"{error_msg}"}
                return response_api_error(http_code=http_code, error=error_msg, headers=headers, endpoint=endpoint_id)
            except Exception as e:
                error_msg = f"{e}"
                http_code = int(HTTPStatus.INTERNAL_SERVER_ERROR.value)
                headers = {"WWW-Authenticate": f"{error_msg}"}
                return response_api_error(http_code=http_code, error=error_msg, headers=headers, endpoint=endpoint_id)
            except BaseException as e:
                error_token = "Token validation failed"
                error_msg = f"Bearer error=\"invalid_token\" error_description=\"{error_token}\""
                error(f"{error_msg}. Exception: {e}")
                http_code = int(HTTPStatus.UNAUTHORIZED.value)
                headers = {"WWW-Authenticate": f"{error_msg}"}
                return response_api_error(http_code=http_code, error=error_msg, headers=headers, endpoint=endpoint_id)

        decorated_function.__name__ = route_function.__name__
        return decorated_function
    return wrapper
