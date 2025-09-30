import requests
from utils.exception_handler import ExceptionHandler

class HttpRequests:
    def __init__(self, logger=None):
        self.logger = logger
    
    @ExceptionHandler.handle_exception
    def post_api_request(self, url, headers=None, data=None, params=None, json=None):

        response = requests.post(url, headers=headers, data=data, params=params, json=json, timeout=120)

        if self.logger:
            self.logger.info(f"POST {url} - Status Code: {response.status_code}")

        valid_status_codes = [200, 201]

        if response.status_code in valid_status_codes:
            if response.content and response.content.strip():
                return response.json()
            else:
                return None
        else:
            try:
                error_details = response.json()
            except ValueError:
                error_details = response.text

            raise requests.exceptions.HTTPError(
                f"{response.status_code} Error: {response.reason} for url: {response.url} | "
                f"Response: {error_details}",
                response=response
            )

    @ExceptionHandler.handle_exception
    def get_api_request(self, url, headers=None, data=None, params=None, json=None):

        # Make the request
        response = requests.get(url, headers=headers, data=data, params=params, json=json)

        if self.logger:
            self.logger.info(f"GET {url} - Status Code: {response.status_code}")

        valid_status_codes = [200, 201]

        # Check if the response status code is in the array
        if response.status_code in valid_status_codes:
            if response.content and response.content.strip():
                return response.json()
            else:
                return None
        else:
            try:
                error_details = response.json()
            except ValueError:
                error_details = response.text

            raise requests.exceptions.HTTPError(
                f"{response.status_code} Error: {response.reason} for url: {response.url} | "
                f"Response: {error_details}",
                response=response
            )

    @ExceptionHandler.handle_exception
    def patch_api_request(self, url, headers=None, data=None, params=None, json=None):

        # Make the request
        response = requests.patch(url, headers=headers, data=data, params=params, json=json)

        if self.logger:
            self.logger.info(f"PATCH {url} - Status Code: {response.status_code}")

        valid_status_codes = [200, 201]

        # Check if the response status code is in the array
        if response.status_code in valid_status_codes:
            if response.content and response.content.strip():
                return response.json()
            else:
                return None
        else:
            try:
                error_details = response.json()
            except ValueError:
                error_details = response.text

            raise requests.exceptions.HTTPError(
                f"{response.status_code} Error: {response.reason} for url: {response.url} | "
                f"Response: {error_details}",
                response=response
            )

    @ExceptionHandler.handle_exception
    def delete_api_request(self, url, headers=None, data=None, params=None, json=None):

        # Make the request
        response = requests.delete(url, headers=headers, data=data, params=params, json=json, timeout=360)

        if self.logger:
            self.logger.info(f"DELETE {url} - Status Code: {response.status_code}")

        valid_status_codes = [200, 204]  # Typically for successful deletion

        # Check if the response status code is in the array
        if response.status_code in valid_status_codes:
            # For successful deletion, typically, there's no response body
            return None
        else:
            try:
                error_details = response.json()
            except ValueError:
                error_details = response.text

            raise requests.exceptions.HTTPError(
                f"{response.status_code} Error: {response.reason} for url: {response.url} | "
                f"Response: {error_details}",
                response=response
            )
    
    @ExceptionHandler.handle_exception
    def put_api_request(self, url, headers=None, data=None, params=None, json=None):

        response = requests.put(url, headers=headers, data=data, params=params, json=json, timeout=120)

        if self.logger:
            self.logger.info(f"PUT {url} - Status Code: {response.status_code}")

        valid_status_codes = [200, 204]  # 204 is for successful update with no content

        # Check if the response status code is in the array
        if response.status_code in valid_status_codes:
            # For successful deletion, typically, there's no response body
            return None
        else:
            try:
                error_details = response.json()
            except ValueError:
                error_details = response.text

            raise requests.exceptions.HTTPError(
                f"{response.status_code} Error: {response.reason} for url: {response.url} | "
                f"Response: {error_details}",
                response=response
            )
