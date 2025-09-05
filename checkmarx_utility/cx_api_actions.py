from checkmarx_utility.cx_api_endpoints import CxApiEndpoints
from checkmarx_utility.cx_config_utility import Config

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests

from urllib.parse import urlencode
import requests
import base64
import sys

class CxApiActions:

    def __init__(self, access_token, logger, configEnvironment=None):
        self.httpRequest = HttpRequests()
        self.apiEndpoints = CxApiEndpoints()
        self.logger = logger
        self.access_token = access_token
        self.config = Config() #"config.env"

        self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url = self.config.get_config()
    
    @ExceptionHandler.handle_exception
    def get_sast_results(self, scan_id, vuln_id=None):

        endpoint = self.apiEndpoints.get_sast_results()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "scan-id": scan_id,
            "result-id": vuln_id
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response

    @ExceptionHandler.handle_exception
    def get_scan_details(self, scan_id):

        endpoint = self.apiEndpoints.get_scan_details(scan_id)
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        response = self.httpRequest.get_api_request(url, headers=headers)
        return response
    
    @ExceptionHandler.handle_exception
    def get_query_descriptions(self, scan_id, query_id):

        endpoint = self.apiEndpoints.get_query_descriptions()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0"
        }

        params = {
            "scan-id": scan_id,
            "ids": query_id
        }

        response = self.httpRequest.get_api_request(url, headers=headers, params=params)
        return response
    
    @ExceptionHandler.handle_exception
    def post_sca_vulnerability_details(self, scan_id, project_id, vuln_id, version):

        endpoint = self.apiEndpoints.get_sca_vuln_details()
        url = f"https://{self.tenant_url}{endpoint}"

        headers = {
            "accept": "application/json; version=1.0",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; version=1.0",
            "cx-authentication-type": "service",
            "cx-project-id": project_id
        }

        json_payload = {
            "query": "query GetVulnerabilitiesByScanId ($scanId: UUID!, $take: Int!, $skip: Int!, $order: [VulnerabilitiesSort!], $where: VulnerabilityModelFilterInput, $isExploitablePathEnabled: Boolean!) {\n  vulnerabilitiesRisksByScanId (\n    scanId: $scanId,\n    take: $take,\n    skip: $skip,\n    order: $order,\n    where: $where,\n    isExploitablePathEnabled: $isExploitablePathEnabled\n  ) {\n    totalCount\n    items {\n      credit\n      state\n      isIgnored\n      cve\n      cwe\n      description\n      packageId\n      severity\n      type\n      published\n      score\n      violatedPolicies\n      isExploitable\n      exploitabilityReason\n      exploitabilityStatus\n      isKevDataExists\n      isExploitDbDataExists\n      vulnerabilityFixResolutionText\n      relation\n      epssData {\n        cve\n        date\n        epss\n        percentile\n      }\n      isEpssDataExists\n      detectionDate\n      isVulnerabilityNew\n      cweInfo {\n        title\n      }\n      packageInfo {\n        name\n        packageRepository\n        version\n      }\n      exploitablePath {\n        methodMatch {\n          fullName\n          line\n          namespace\n          shortName\n          sourceFile\n        }\n        methodSourceCall {\n          fullName\n          line\n          namespace\n          shortName\n          sourceFile\n        }\n      }\n      vulnerablePackagePath {\n        id\n        isDevelopment\n        isResolved\n        name\n        version\n        vulnerabilityRiskLevel\n      }\n      references {\n        comment\n        type\n        url\n      }\n      cvss2 {\n        attackComplexity\n        attackVector\n        authentication\n        availability\n        availabilityRequirement\n        baseScore\n        collateralDamagePotential\n        confidentiality\n        confidentialityRequirement\n        exploitCodeMaturity\n        integrityImpact\n        integrityRequirement\n        remediationLevel\n        reportConfidence\n        targetDistribution\n      }\n      cvss3 {\n        attackComplexity\n        attackVector\n        availability\n        availabilityRequirement\n        baseScore\n        confidentiality\n        confidentialityRequirement\n        exploitCodeMaturity\n        integrity\n        integrityRequirement\n        privilegesRequired\n        remediationLevel\n        reportConfidence\n        scope\n        userInteraction\n      }\n      cvss4 {\n        attackComplexity\n        attackVector\n        attackRequirements\n        baseScore\n        privilegesRequired\n        userInteraction\n        vulnerableSystemConfidentiality\n        vulnerableSystemIntegrity\n        vulnerableSystemAvailability\n        subsequentSystemConfidentiality\n        subsequentSystemIntegrity\n        subsequentSystemAvailability\n      }\n      pendingState\n      pendingChanges\n      packageState {\n        type\n        value\n      }\n      pendingScore\n      pendingSeverity\n      isScoreOverridden\n    }\n  }\n}",
            "variables": {
                "scanId": scan_id,
                "take": 10,
                "skip": 0,
                "order": [
                    { "score": "DESC" }
                ],
                "where": {
                "packageInfo": {
                    "and": [
                    { "name": { "eq": vuln_id } },
                    { "version": { "eq": version } }
                    ]
                }
                },
                "isExploitablePathEnabled": True
            }
        }

        response = self.httpRequest.post_api_request(url, headers=headers, json=json_payload)
        return response

# -------------- Not being used ------------------
    
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
        
    