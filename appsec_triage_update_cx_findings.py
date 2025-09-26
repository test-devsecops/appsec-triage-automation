from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager
from utils.helper_functions import HelperFunctions

from utils.logger import Logger
from urllib.parse import urlparse, parse_qs

import os
import sys
import json

def _get_cx_state_and_severity(triage_values_mapping, triage_status):
    triage_value = triage_values_mapping.get(triage_status, {})
    cx_state = triage_value.get('state')
    cx_severity = triage_value.get('severity', None)
    return cx_state, cx_severity

def main():
    """
    Main entry point for vulnerability details extraction.
    """
    # ------------- JIRA AUTOMATION PAYLOAD TESTING VARIABLES ----------------- #

    TEST_SCAN_ID = "e5421550-fdc2-4b13-b85d-866f136a751c"
    TEST_VULN_ID = "ysTAGGDe/mRAJty/2BEXEUhNeTo="
    TEST_PACKAGE_NAME = "libc-bin:2.36-9+deb12u10" #"multer 1.4.5-lts.2"
    TEST_TRIAGE_STATUS = "Downgrade to High" #"False Positive" #"Downgrade to High", "Downgrade to Medium", "Downgrade to Low"
    TEST_COMMENT = "This is a test comment 2"
    
    # DAST
    TEST_RESULTS_URL = [
        'https://eu-2.ast.checkmarx.net/applicationsAndProjects/environments/685226be-f5bb-4134-8175-bb6b3ff2d8a7/1b5b040b-f8ba-4927-827f-3b63d4d2452a?resultId=2bbf6cd9e29c747c3234569298a051ee2c70fbbf20646faaf33b5da279644749',
        'https://eu-2.ast.checkmarx.net/applicationsAndProjects/environments/685226be-f5bb-4134-8175-bb6b3ff2d8a7/1b5b040b-f8ba-4927-827f-3b63d4d2452a?resultId=2d37be733dbc95e121f16b7960e75f5d543cefba7c0bc5a026e65881059e0191&tableConfig=%7B%22search%22%3A%7B%22text%22%3A%22%22%7D%2C%22sorting%22%3A%7B%22columnKey%22%3A%22severity%22%2C%22order%22%3A%22descend%22%7D%2C%22filters%22%3A%7B%22state%22%3A%5B%22To+Verify%22%2C%22Proposed+Not+Exploitable%22%2C%22Urgent%22%2C%22Confirmed%22%5D%7D%2C%22pagination%22%3A%7B%22pageSize%22%3A10%2C%22currentPage%22%3A1%7D%2C%22grouping%22%3A%7B%22groups%22%3A%5B%5D%2C%22groupsState%22%3A%5B%5D%7D%7D'
    ]

    SCAN_TYPE_SAST = "SAST"
    SCAN_TYPE_SCA = "SCA"
    SCAN_TYPE_CSEC = "CSEC"
    SCAN_TYPE_DAST = "DAST"

    scan_type = SCAN_TYPE_SAST  # Change as needed for testing

    # ------------- JIRA AUTOMATION PAYLOAD TESTING VARIABLES ----------------- #

    log = Logger("appsec_triage")
    access_token_manager = AccessTokenManager(logger=log)
    access_token = access_token_manager.get_valid_token()
    cx_api_actions = CxApiActions(access_token=access_token, logger=log)
    helper = HelperFunctions()

    # JIRA to CX Mapping
    triage_values_mapping = {
        "False Positive": {"state": "NOT_EXPLOITABLE"},
        "Downgrade to High": {"state": "CONFIRMED", "severity": "HIGH"},
        "Downgrade to Medium": {"state": "CONFIRMED", "severity": "MEDIUM"},
        "Downgrade to Low": {"state": "CONFIRMED", "severity": "LOW"},
    }

    if scan_type == SCAN_TYPE_DAST:
        log.info(f"Scan Type: {scan_type}")
        
    else:

        scan_details = cx_api_actions.get_scan_details(TEST_SCAN_ID)
        if scan_details is None:
            log.error(f"Scan ID {TEST_SCAN_ID} is empty or does not exist")
            return
        
        project_id = scan_details.get('projectId')
        scan_id = scan_details.get('id')

        if scan_type == SCAN_TYPE_SAST:
            log.info(f"Scan Type: {scan_type}")

            scan_results = cx_api_actions.get_sast_results(TEST_SCAN_ID, TEST_VULN_ID)
            if scan_results is None:
                log.error(f"Scan ID {TEST_SCAN_ID} is empty or does not exist")
                return
            
            cx_state, cx_severity = _get_cx_state_and_severity(triage_values_mapping, TEST_TRIAGE_STATUS)

            for result in scan_results.get('results'):
                similarity_id = result.get('similarityID')
                log.info(f"Similarity ID: {similarity_id}")
                
                sast_predicate_response = cx_api_actions.post_sast_predicates(similarity_id, project_id, scan_id, cx_severity, cx_state, TEST_COMMENT)

                # Expecting None 
                if sast_predicate_response is None:
                    log.info(f"Successfully updated the state and severity of Vulnerability ID: {TEST_VULN_ID}")
                else:
                    log.error(f"Failed to update the state and severity of Vulnerability ID: {TEST_VULN_ID}")

        elif scan_type == SCAN_TYPE_SCA:
            log.info(f"Scan Type: {scan_type}")
            

        elif scan_type == SCAN_TYPE_CSEC:
            log.info(f"Scan Type: {scan_type}")
            
            
        else:
            log.warning(f"The {scan_type} Scan type is not supported by this workflow automation.")

if __name__ == "__main__":
    main()
