from jira_utility.jira_api_endpoints import JiraApiEndpoints
from jira_utility.jira_config_utility import Config

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests

from urllib.parse import urlencode

import requests
import base64
import sys


class JiraApiActions:

    def __init__(self, configEnvironment=None):
        self.httpRequest = HttpRequests()
        self.apiEndpoints = JiraApiEndpoints()
        self.config = Config()

        self.token, self.project_id, self.jira_url, self.issuetype_id = self.config.get_config(configEnvironment)

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
    def create_issue(self, fields_values):

        endpoint = self.apiEndpoints.create_issue()
        url = f"https://{self.jira_url}{endpoint}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        description_text = ""
        # # Format the description dictionary into a string. This is temporary and can be removed or changed in the future.
        # description_text = "\n".join(
        #     f"{key}: {value}" for key, value in fields_values['description'].items()
        # )

        payload = {
            "fields": {
                "project": {
                    "id": self.project_id
                },
                "issuetype": {
                    "id": self.issuetype_id
                },
                "description": description_text,
                "summary": fields_values["summary"],
                "customfield_16500" : fields_values["lbu"],
                "customfield_16501" : fields_values["project_name"],
                "customfield_16704" : fields_values["application_name"],
                "customfield_16504" : fields_values["scan_report_link"],
                "customfield_16700" : fields_values["num_of_critical"],
                "customfield_16701" : fields_values["num_of_high"],
                "customfield_16702" : fields_values["num_of_medium"],
                "customfield_16703" : fields_values["num_of_low"],
            }
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=payload)
        return response