import sys
from http import HTTPStatus


class OceanaError(Exception):
    """
    Base exception for all errors.

    :param object message: The message object stringified as 'message' attribute
    :keyword error: The original exception if any
    :paramtype error: Exception

    :ivar inner_exception: The exception passed with the 'error' kwarg
    :vartype inner_exception: Exception
    :ivar exc_type: The exc_type from sys.exc_info()
    :ivar exc_value: The exc_value from sys.exc_info()
    :ivar exc_traceback: The exc_traceback from sys.exc_info()
    :ivar exc_msg: A string formatting of message parameter, exc_type and exc_value
    :ivar str message: A stringified version of the message parameter
    """

    def __init__(self, message, *args, **kwargs) -> None:
        self.inner_exception = kwargs.get("error")

        exc_info = sys.exc_info()
        self.exc_type = exc_info[0]
        self.exc_value = exc_info[1]
        self.exc_traceback = exc_info[2]

        self.exc_type = self.exc_type if self.exc_type else type(self.inner_exception)
        self.exc_msg: str = "{}, {}: {}".format(message, self.exc_type.__name__, self.exc_value)
        self.message: str = str(message)
        super().__init__(self.message, *args)


class ServiceRequestError(OceanaError):
    """
    An error occurred while attempt to make a request to the service. (with status code 400)
    No request was sent.
    """


class ServiceResponseError(OceanaError):
    """
    The request was sent, but the client failed to understand the response.
    The connection may have timed out. These errors can be retried for idempotent or
    safe operations
    """


class ServiceRequestTimeoutError(ServiceRequestError):
    """
    Error raised when timeout happens
    """


class ServiceResponseTimeoutError(ServiceResponseError):
    """
    Error raised when timeout happens
    """


class HttpResponseError(OceanaError):
    """
    A request was made, and a non-success status code was received from the service.

    :param object message: The message object stringified as 'message' attribute
    :param response: The response that triggered the exception.
    """

    # def __init__(self, message=None, response=None, **kwargs) -> None:
    def __init__(self,
                 status_code: int,
                 error: str,
                 message: str,
                 response=None,
                 **kwargs) -> None:

        self.status_code = status_code
        self.message = message
        self.error = error
        self.response = response
        self.reason = kwargs.get("reason")

        if response:
            self.reason = response.reason
            self.status_code = response.status_code

        super().__init__(message=message,
                         error=error,
                         **kwargs)

    def error_description(self):
        """
        Error description to add to header `WWW-Authenticate`
        """
        return f"error=\"{self.error}\" error_description=\"{self.message}\""


# 401 UNAUTHORIZED
class ClientAuthenticationError(HttpResponseError):
    """
    An client error response code 401 UNAUTHORIZED
    """
    def __init__(self, message, error="invalid_token", response=None, **kwargs) -> None:
        super().__init__(status_code=int(HTTPStatus.UNAUTHORIZED.value),
                         error=error,
                         message=message,
                         response=response,
                         **kwargs)


# Oauth2 errors
class ClientJWTDecodeException(ClientAuthenticationError):
    """
    Decode error response code 401 UNAUTHORIZED
    """
    def __init__(self, message, response=None, **kwargs) -> None:
        super().__init__(message=message,
                         error="invalid_token",
                         response=response, **kwargs)


class ClientIssuerException(ClientAuthenticationError):
    """
    Invalid issuer error response code 401 UNAUTHORIZED
    """
    def __init__(self, message, response=None, **kwargs) -> None:
        super().__init__(message=message,
                         error="invalid_token",
                         response=response, **kwargs)


# 400 BAD_REQUEST
class ClientBadRequestException(HttpResponseError):
    """
    An bad request error with response code 400 BAD_REQUEST
    """
    def __init__(self, message, response=None, **kwargs) -> None:
        super().__init__(status_code=int(HTTPStatus.BAD_REQUEST.value),
                         error="invalid_request",
                         message=message,
                         response=response,
                         **kwargs)


class ClientInvalidSignatureException(ClientBadRequestException):
    """
    Invalid signature error response code 400 BAD_REQUEST
    """
    def __init__(self, message, response=None, **kwargs) -> None:
        super().__init__(message=message,
                         response=response, **kwargs)
