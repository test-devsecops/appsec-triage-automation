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

    def __init__(self, logger):
        self.logger = logger
        self.httpRequest = HttpRequests(logger)
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
    def comment_issue(self, comment_message, issue_key):
        endpoint = self.apiEndpoints.comment_issue(issue_key)
        url = f"https://{self.jira_url}{endpoint}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        payload = { 
            "body": comment_message 
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
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
    def create_subtask(self, added_payload, subtask_id):

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
                    "name": subtask_id
                },
                "description" : "Sub-task"
            }
        }

        payload["fields"].update(added_payload)
        # print(json.dumps(payload))

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
        return response

    def populate_exception_comment_issue(self, jira_issue: str, log: Logger, scan_id: str = None, error_message: str = None):
        try:
            if scan_id and error_message:
                message = f"[ERROR] Population Error | Failed to fetch scan details for scan_id: {scan_id}. Error: {error_message}."
            elif scan_id:
                message = f"[ERROR] Population Error | Failed to fetch scan details for scan_id: {scan_id}."
            else:
                message = "[ERROR] Population Error |  An unexpected error occurred. Please notify adminstrator."
            
            self.comment_issue(message, jira_issue)
            log.info(f"Commented Ticket {jira_issue} with error.")
        except Exception as e:
            log.error(f"Failed to comment issue with error : {e}")

    def update_exception_comment_issue(self, jira_issue: str, log: Logger, error_message: str = None):
        try:
            message = f"[ERROR] Update Error | Failed to Triage. Error: {error_message}."
           
            self.comment_issue(message, jira_issue)
            log.info(f"Commented on Ticket {jira_issue} with error.")
        except Exception as e:
            log.error(f"Failed to comment issue with error : {e}")

    def update_successful_comment_issue(self, jira_issue: str, log: Logger, stage: bool):
        try:
            if stage == True:
                message = f"[SUCCESS] Population Success"
            else:
                message = f"[SUCCESS] Triage Update Success"
           
            self.comment_issue(message, jira_issue)
            log.info(f"Commented on Ticket {jira_issue} with success.")
        except Exception as e:
            log.error(f"Failed to comment issue : {e}")


        
