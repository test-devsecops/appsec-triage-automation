from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager
from utils.helper_functions import HelperFunctions
from checkmarx_utility.cx_helper_functions import CxHelperFunctions
from utils.logger import Logger

import os
import sys
import json

def _get_cx_state_severity_score(triage_values_mapping, triage_status):
    """
    For CSEC only: returns (state, severity, score) where score is the string from the mapping (not converted).
    """
    triage_value = triage_values_mapping.get(triage_status, {})
    cx_state = triage_value.get('state')
    cx_severity = triage_value.get('severity', None)
    cx_score = triage_value.get('score', None)  # For CSEC, score is just the severity string from the mapping
    return cx_state, cx_severity, cx_score

def main():
    """
    Main entry point for vulnerability details extraction.
    """
    # ------------- JIRA AUTOMATION PAYLOAD TESTING VARIABLES ----------------- #

    TEST_TRIAGE_STATUS = "Downgrade to High" #"False Positive" #"Downgrade to High", "Downgrade to Medium", "Downgrade to Low"
    TEST_COMMENT = "This is a test comment 2"
    TEST_SCAN_ID = "0b14a69a-a6db-470c-ae75-190a45446859" #"e5421550-fdc2-4b13-b85d-866f136a751c"

    # SAST
    TEST_SAST_VULN_ID = "ysTAGGDe/mRAJty/2BEXEUhNeTo="

    # SCA
    TEST_SCA_PACKAGE_NAME = "multer 1.4.5-lts.2"
    TEST_SCA_CVE_ID = "CVE-2025-47935"

    # CSEC
    TEST_CSEC_PACKAGE_ID = "libc-bin:2.36-9+deb12u10"
    TEST_CSEC_CVE_ID = "CVE-2025-5702"
    
    # DAST
    TEST_DAST_RESULT_URL = 'https://eu-2.ast.checkmarx.net/applicationsAndProjects/environments/685226be-f5bb-4134-8175-bb6b3ff2d8a7/1b5b040b-f8ba-4927-827f-3b63d4d2452a?resultId=2bbf6cd9e29c747c3234569298a051ee2c70fbbf20646faaf33b5da279644749&tableConfig=%7B%22search%22%3A%7B%22text%22%3A%22%22%7D%2C%22sorting%22%3A%7B%22columnKey%22%3A%22severity%22%2C%22order%22%3A%22descend%22%7D%2C%22filters%22%3A%7B%22state%22%3A%5B%22To+Verify%22%2C%22Proposed+Not+Exploitable%22%2C%22Urgent%22%2C%22Confirmed%22%5D%7D%2C%22pagination%22%3A%7B%22pageSize%22%3A10%2C%22currentPage%22%3A1%7D%2C%22grouping%22%3A%7B%22groups%22%3A%5B%5D%2C%22groupsState%22%3A%5B%5D%7D%7D'

    SCAN_TYPE_SAST = "SAST"
    SCAN_TYPE_SCA = "SCA"
    SCAN_TYPE_CSEC = "CSEC"
    SCAN_TYPE_DAST = "DAST"

    scan_type = SCAN_TYPE_CSEC  # Change as needed for testing

    # ------------- JIRA AUTOMATION PAYLOAD TESTING VARIABLES ----------------- #

    log = Logger("appsec_triage")
    access_token_manager = AccessTokenManager(logger=log)
    access_token = access_token_manager.get_valid_token()
    cx_api_actions = CxApiActions(access_token=access_token, logger=log)
    helper = HelperFunctions()
    cx_helper = CxHelperFunctions()

    if scan_type == SCAN_TYPE_DAST:
        log.info(f"Scan Type: {scan_type}")

        # Extract result id and scan id from the URL
        result_ids = cx_helper.extract_ids_from_result_url(TEST_DAST_RESULT_URL)
        result_id = result_ids.get('result_id')
        scan_id = result_ids.get('scan_id')
        environment_id = result_ids.get('environment_id')
       
        # Check if the scan id provided by the user is the same as the scan IDs from the URL
        if TEST_SCAN_ID != result_ids.get('scan_id'):
            log.error(f"Scan ID {TEST_SCAN_ID} did not match the scan ID from the URL")
            return
        
        # Check if the scan id provided by the user really exists
        result_info = cx_api_actions.get_dast_scan_result_detailed_info(result_id, scan_id)
        if result_info is None:
            log.error(f"Scan ID {TEST_SCAN_ID} is empty or does not exist")
            return

        # JIRA to CX Mapping
        dast_triage_values_mapping = {
            "False Positive": {"state": "Not Exploitable"},
            "Downgrade to High": {"state": "Confirmed", "severity": "HIGH"},
            "Downgrade to Medium": {"state": "Confirmed", "severity": "MEDIUM"},
            "Downgrade to Low": {"state": "Confirmed", "severity": "LOW"},
        }

        cx_state, cx_severity, cx_score = _get_cx_state_severity_score(dast_triage_values_mapping, TEST_TRIAGE_STATUS)
        dast_update_response = cx_api_actions.post_dast_result_update(environment_id, [result_id], scan_id, cx_severity, cx_state, TEST_COMMENT)
        wrapped_result_id = helper.shorten_strings_middle(str(result_id))

        if dast_update_response == "OK":
            log.info(f"[DAST] Successfully updated the state and severity of Result ID: {wrapped_result_id} to State: {cx_state} Severity: {cx_severity}")
        else:
            log.error(f"[DAST] Failed to update the state and severity of Result ID: {wrapped_result_id}")

    else:

        scan_details = cx_api_actions.get_scan_details(TEST_SCAN_ID)
        if scan_details is None:
            log.error(f"Scan ID {TEST_SCAN_ID} is empty or does not exist")
            return
        
        project_id = scan_details.get('projectId')
        scan_id = scan_details.get('id')

        if scan_type == SCAN_TYPE_SAST:
            log.info(f"Scan Type: {scan_type}")

            # JIRA to CX Mapping
            sast_triage_values_mapping = {
                "False Positive": {"state": "NOT_EXPLOITABLE"},
                "Downgrade to High": {"state": "CONFIRMED", "severity": "HIGH"},
                "Downgrade to Medium": {"state": "CONFIRMED", "severity": "MEDIUM"},
                "Downgrade to Low": {"state": "CONFIRMED", "severity": "LOW"},
            }

            scan_results = cx_api_actions.get_sast_results(TEST_SCAN_ID, TEST_SAST_VULN_ID)
            if scan_results is None:
                log.error(f"Scan ID {TEST_SCAN_ID} is empty or does not exist")
                return
            
            cx_state, cx_severity, cx_score = _get_cx_state_severity_score(sast_triage_values_mapping, TEST_TRIAGE_STATUS)

            for result in scan_results.get('results'):
                similarity_id = result.get('similarityID')
                log.info(f"Similarity ID: {similarity_id}")
                
                sast_predicate_response = cx_api_actions.post_sast_predicates(similarity_id, project_id, scan_id, cx_severity, cx_state, TEST_COMMENT)
                wrapped_similarity_id = helper.shorten_strings_middle(str(similarity_id))

                # Expecting None 
                if sast_predicate_response is None:
                    log.info(f"[SAST] Successfully updated the state and severity of Vulnerability ID: {wrapped_similarity_id} to State: {cx_state} Severity: {cx_severity}")
                else:
                    log.error(f"[SAST] Failed to update the state and severity of Vulnerability ID: {wrapped_similarity_id}")

        elif scan_type == SCAN_TYPE_SCA:
            log.info(f"Scan Type: {scan_type}")

            # JIRA to CX Mapping
            sca_triage_values_mapping = {
                "False Positive": {"state": "NotExploitable"},
                "Downgrade to High": {"state": "Confirmed", "severity": "7"},
                "Downgrade to Medium": {"state": "Confirmed", "severity": "4"},
                "Downgrade to Low": {"state": "Confirmed", "severity": "0.1"},
            }

            package_name, package_version = cx_helper.set_package_and_version(TEST_SCA_PACKAGE_NAME)
            cx_state, cx_severity, cx_score = _get_cx_state_severity_score(sca_triage_values_mapping, TEST_TRIAGE_STATUS)

            sca_vuln_details = cx_api_actions.get_sca_vulnerability_details_with_CVE_graphql(scan_id, project_id, package_name, package_version, TEST_SCA_CVE_ID)
            cve_details = helper.get_nested(sca_vuln_details, ['data', 'vulnerabilitiesRisksByScanId', 'items'])
            package_repo = cve_details[0].get('packageInfo').get('packageRepository')
            package_id = cve_details[0].get('packageId')

            change_state_action = cx_api_actions.post_sca_management_of_risk(package_name, package_version, package_repo, TEST_SCA_CVE_ID, project_id, 'ChangeState', cx_state, TEST_COMMENT)
            change_score_action = cx_api_actions.post_sca_management_of_risk(package_name, package_version, package_repo, TEST_SCA_CVE_ID, project_id, 'ChangeScore', cx_severity, TEST_COMMENT)
            
            # Expecting None 
            if change_state_action is None and change_score_action is None:
                log.info(f"[SCA] Successfully updated the state and severity of Package: {package_id} to State: {cx_state} Severity: {cx_severity}")
            else:
                log.error(f"[SCA] Failed to update the state and severity of Package: {package_id}")

        elif scan_type == SCAN_TYPE_CSEC:
            log.info(f"Scan Type: {scan_type}")

            images = cx_api_actions.get_image_id_graphql(scan_id, project_id)
            image = helper.get_nested(images, ['data', 'images', 'items'])
            image_id = image[0].get('imageId')

            # JIRA to CX Mapping
            csec_triage_values_mapping = {
                "False Positive": {"state": "NotExploitable"},
                "Downgrade to High": {"state": "Confirmed", "severity": "High", "score": 7},
                "Downgrade to Medium": {"state": "Confirmed", "severity": "Medium", "score": 4},
                "Downgrade to Low": {"state": "Confirmed", "severity": "Low", "score": 0.1},
            }

            cx_state, cx_severity, cx_score = _get_cx_state_severity_score(csec_triage_values_mapping, TEST_TRIAGE_STATUS)

            csec_vuln_details = cx_api_actions.get_csec_vulnerability_details_graphql(scan_id, project_id, image_id, TEST_CSEC_PACKAGE_ID)
            image_vuln_details = helper.get_nested(csec_vuln_details, ['data', 'imagesVulnerabilities', 'items'])
            vuln_item_id = image_vuln_details[0].get('id')
            package_id = image_vuln_details[0].get('packageId')
            
            csec_triage_vuln_update = cx_api_actions.post_csec_vulnerability_triage_update(cx_state, cx_severity, cx_score, TEST_COMMENT, scan_id, project_id, vuln_item_id, TEST_CSEC_CVE_ID)

            if csec_triage_vuln_update is not None:
                if csec_triage_vuln_update.get('success') is True:
                    log.info(f"[CSEC] Successfully updated the state and severity of Package: {package_id} to State: {cx_state} Severity: {cx_severity}")
            else:
                log.error(f"[CSEC] Failed to update the state and severity of Package: {package_id}")
            
        else:
            log.warning(f"The {scan_type} Scan type is not supported by this workflow automation.")

if __name__ == "__main__":
    main()
