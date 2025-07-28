
from checkmarx_utility.cx_api_endpoints import CxApiEndpoints
from checkmarx_utility.cx_config_utility import Config

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests

from urllib.parse import urlencode

import requests
import base64
import sys

class CxApiActions:

    def __init__(self, configEnvironment=None):
        self.httpRequest = HttpRequests()
        self.apiEndpoints = CxApiEndpoints()
        self.config = Config() #"config.env"

        self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url = self.config.get_config(configEnvironment)

    @ExceptionHandler.handle_exception
    def get_access_token(self):

        endpoint = self.apiEndpoints.get_access_token(self.tenant_name)
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        data = {
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": self.token
        }

        encoded_data = urlencode(data)

        response = self.httpRequest.post_api_request(url, headers, encoded_data)
        print("Successfully generated a token")

        return response.get("access_token")
    
    @ExceptionHandler.handle_exception
    def get_scan_summary(self, access_token, scan_ids):

        endpoint = self.apiEndpoints.get_scan_summary()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "scan-ids": [scan_ids]
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response
    
    @ExceptionHandler.handle_exception
    def get_scans_by_tags_keys(self, access_token, tags):

        endpoint = self.apiEndpoints.get_scans()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }
        
        params = tags
        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response
    
    @ExceptionHandler.handle_exception
    def get_application_by_id(self, access_token, application_id):
        endpoint = self.apiEndpoints.get_application_info(application_id)
        
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response

    @ExceptionHandler.handle_exception
    def get_project_info_by_id(self, access_token, project_id):
        
        endpoint = self.apiEndpoints.get_project_info(project_id)
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response

    @ExceptionHandler.handle_exception
    def update_scan_tags(self, access_token, scan_id, tags_dict):
        
        endpoint = self.apiEndpoints.update_scan_tags(scan_id)
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        payload = {
            "tags": tags_dict
        }

        response = self.httpRequest.put_api_request(url, headers=headers, json=payload)
        return response






    @ExceptionHandler.handle_exception
    def get_tenant_url(self):
        return self.tenant_url
        
    