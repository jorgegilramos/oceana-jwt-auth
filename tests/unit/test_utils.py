from oceana_jwt_auth import string_base64, base64_string, \
    info, debug, error, warning, critical
from oceana_jwt_auth.utils.logger import AppLogger


def test_string_base64():
    result = string_base64(s="Test string")
    assert isinstance(result, bytes)
    assert result == b"VGVzdCBzdHJpbmc="


def test_base64_string():
    result = base64_string(b=b"VGVzdCBzdHJpbmc=")
    assert isinstance(result, str)
    assert result == "Test string"


def test_logger_init():
    logger1 = AppLogger(__name__)
    # Avoid log double initialization
    logger1.__init__(__name__)
    AppLogger.__init__(logger1, __name__)


def test_logger_functions():
    message = "Log test message"
    info(message)
    debug(message)
    error(message)
    warning(message)
    critical(message)
