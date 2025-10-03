from jira_utility.jira_api_endpoints import JiraApiEndpoints
from jira_utility.jira_config_utility import Config

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests

from urllib.parse import urlencode

from utils.logger import Logger

import requests
import base64
import sys
import json


class JiraApiActions:

    def __init__(self):
        self.httpRequest = HttpRequests()
        self.apiEndpoints = JiraApiEndpoints()
        self.config = Config()

        self.token, self.project_id, self.jira_url = self.config.get_config()

    @ExceptionHandler.handle_exception
    def get_queues(self):

        endpoint = self.apiEndpoints.get_queues(self.project_id)
        url = f"https://{self.jira_url}{endpoint}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        response = self.httpRequest.get_api_request(url, headers)
        return response

    @ExceptionHandler.handle_exception
    def get_issue(self, issue_key):

        endpoint = self.apiEndpoints.get_issue(issue_key)
        url = f"https://{self.jira_url}{endpoint}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        response = self.httpRequest.get_api_request(url, headers)
        return response


    @ExceptionHandler.handle_exception
    def update_issue(self, added_payload, issue_key):
        endpoint = self.apiEndpoints.update_issue(issue_key)
        url = f"https://{self.jira_url}{endpoint}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        payload = { 
            "fields": {
            }
        }

        payload["fields"].update(added_payload)
        # print(json.dumps(payload))

        response = self.httpRequest.put_api_request(url, headers=headers, json=payload)
        return response

    @ExceptionHandler.handle_exception
    def create_subtask(self, added_payload):

        endpoint = self.apiEndpoints.create_issue()
        url = f"https://{self.jira_url}{endpoint}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        payload = { 
            "fields": {
                "project": {
                    "id": self.project_id 
                },
                
                "issuetype": {
                    "name": "Sub-task"
                },
                "description" : "Sub-task"
            }
        }

        payload["fields"].update(added_payload)
        # print(json.dumps(payload))

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
        return response

    def exception_update_description(self, jira_issue: str, log: Logger, scan_id: str = None, error_message: str = None):
        if scan_id and error_message:
            description = f"[ERROR] Failed to fetch scan details for scan_id: {scan_id}. Error: {error_message}."
        elif scan_id:
            description = f"[ERROR] Failed to fetch scan details for scan_id: {scan_id}."
        else:
            description = "[ERROR] An unexpected error occurred. Please notify adminstrator."

        added_payload = {
            'description': description
        }
        try:
            self.update_issue(added_payload, jira_issue)
            log.info(f"Updated Ticket {jira_issue} with error.")
        except Exception as e:
            log.error(f"Failed to update issue with error : {e}")

