import requests
import time
import functools
import sys
import traceback

class ExceptionHandler:
    @staticmethod
    def handle_exception(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self = args[0] if args else None
            logger = getattr(self, "logger", None)

            try:
                return func(*args, **kwargs)
            except Exception as err:
                exc_type, exc_value, exc_tb = sys.exc_info()
                tb = traceback.extract_tb(exc_tb)
                if tb:
                    last_frame = tb[-1]
                    filename = last_frame.filename
                    lineno = last_frame.lineno
                    funcname = last_frame.name
                else:
                    filename = funcname = lineno = "Unknown"
                if isinstance(err, requests.exceptions.HTTPError):
                    err_type = "HTTP Error"
                elif isinstance(err, requests.exceptions.RequestException):
                    err_type = "RequestException"
                else:
                    err_type = "Unexpected Error"
                msg = (f"{err_type}: {err} | "
                       f"File: {filename} | Function: {funcname} | Line: {lineno}")
                if logger:
                    logger.error(msg)
                else:
                    print(msg)
            return None
        return wrapper

    @staticmethod
    def handle_exception_with_retries(retries=1, delay=1.3):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                self = args[0] if args else None
                logger = getattr(self, "logger", None)

                attempt = 0
                while attempt < retries:
                    try:
                        return func(*args, **kwargs)
                    except Exception as err:
                        exc_type, exc_value, exc_tb = sys.exc_info()
                        tb = traceback.extract_tb(exc_tb)
                        if tb:
                            last_frame = tb[-1]
                            filename = last_frame.filename
                            lineno = last_frame.lineno
                            funcname = last_frame.name
                        else:
                            filename = funcname = lineno = "Unknown"
                        if isinstance(err, requests.exceptions.HTTPError):
                            err_type = "HTTP Error"
                        elif isinstance(err, requests.exceptions.RequestException):
                            err_type = "RequestException"
                        else:
                            err_type = "Unexpected Error"
                        msg = (f"{err_type}: {err} | "
                               f"File: {filename} | Function: {funcname} | Line: {lineno}")

                    attempt += 1
                    if logger:
                        logger.error(f"{msg} | Retry {attempt}/{retries}")
                    else:
                        print(f"{msg} | Retry {attempt}/{retries}")

                    if attempt < retries:
                        time.sleep(delay)
                return None
            return wrapper
        return decorator
