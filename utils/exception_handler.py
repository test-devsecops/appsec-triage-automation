import requests
import time
import functools

class ExceptionHandler:
    @staticmethod
    def handle_exception(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            self = args[0] if args else None
            logger = getattr(self, "logger", None)

            try:
                return func(*args, **kwargs)
            except requests.exceptions.HTTPError as err:
                msg = f"HTTP Error: {err}"
            except requests.exceptions.RequestException as err:
                msg = f"RequestException error occurred: {err}"
            except Exception as err:
                msg = f"An unexpected error occurred: {err}"

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
                    except requests.exceptions.HTTPError as err:
                        msg = f"HTTP Error: {err}"
                    except requests.exceptions.RequestException as err:
                        msg = f"RequestException error occurred: {err}"
                    except Exception as err:
                        msg = f"An unexpected error occurred: {err}"

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
