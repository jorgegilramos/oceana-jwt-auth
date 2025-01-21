import base64
from .logger import logger


def string_base64(s):
    return base64.b64encode(s.encode("utf-8")) if isinstance(s, str) else None


def base64_string(b):
    return base64.b64decode(b).decode("utf-8") if isinstance(b, bytes) else None


# Shortcut to logger functions
def info(message, *args, **kwargs):
    logger.info(message, *args, **kwargs)


def debug(message, *args, **kwargs):
    logger.debug(message, *args, **kwargs)


def error(message, *args, **kwargs):
    logger.error(message, *args, **kwargs)


def warning(message, *args, **kwargs):
    logger.warning(message, *args, **kwargs)


def critical(message, *args, **kwargs):
    logger.critical(message, *args, **kwargs)
