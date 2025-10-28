from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager
from jira_utility.jira_helper_functions import JiraHelperFunctions
from utils.helper_functions import HelperFunctions
from checkmarx_utility.cx_helper_functions import CxHelperFunctions
from utils.logger import Logger
import argparse
from utils.yml_file_utility import load_map

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

    log = Logger("appsec_triage")
    # ------------- JIRA AUTOMATION PAYLOAD TESTING VARIABLES ----------------- #
    try:
        parser = argparse.ArgumentParser(
            description="AppSec Triage Script"
        )
        parser.add_argument("jira_issue", help="Jira Issue Key e.g. ABC-123")
        args = parser.parse_args()
        jira_issue = args.jira_issue

        print(f"Jira issue: {jira_issue}")
        # print(f"Scan Engine: {scan_engine}")
        # print(f"Ref Number: {reference_number if reference_number else 'N/A'}")

        TRIAGE_UPDATE_STAGE = False

        jira_api_actions = JiraApiActions(log)

        try:
            jira_issue_data = jira_api_actions.get_issue(jira_issue)
            jira_issue_fields = jira_issue_data.get("fields")
            jira_issue_fields = JiraHelperFunctions.remove_all_null_key_values(jira_issue_fields)
        except Exception as e:
            log.error(f"Failed to fetch or process Jira issue data: {e}")
            jira_api_actions.populate_exception_comment_issue(jira_issue, log)
            return 1
        
        try:
            field_map = load_map('config/field_mapping.yml',parent_field='fields')
            # user_type = load_map('config/user_type.yml',parent_field='user_type')
        except Exception as e:
            log.error(f"Failed to load yaml mapping: {e}")
            jira_api_actions.populate_exception_comment_issue(jira_api_actions, jira_issue, log)
            return 1

        # Extracting data to be readable
        parent_data = {}
        for key, value in jira_issue_fields.items():
            for field_key, field_value in field_map.items():
                if field_value == key:
                    parent_data[field_key] = value
                if key == 'summary':
                    parent_data['summary'] = value
    
        # print(json.dumps(parent_data,indent=2))

        scan_engine = parent_data.get('summary').split('|')[0].strip()
        print(f"Scan Engine: {scan_engine}")

        # TRIAGE_STATUS = "Downgrade to High" #"False Positive" #"Downgrade to High", "Downgrade to Medium", "Downgrade to Low"
        TRIAGE_STATUS = parent_data.get("triage_status", {}).get("value",None)

        if TRIAGE_STATUS is None or TRIAGE_STATUS.lower() == 'please select value' :
            raise ValueError("Triage status hasn't been selected, or empty")

        # JUSTIFICATION = "This is a test comment 2"
        JUSTIFICATION = parent_data.get("justification",None)
        
        if JUSTIFICATION is None or JUSTIFICATION.lower() == 'please input justification':
            raise ValueError("No Justification found")

        SCAN_ID = parent_data.get("scan_id")

        # SAST
        SAST_VULN_ID = parent_data.get("vulnerability")


        # SCA
        SCA_PACKAGE_NAME = parent_data.get("package_name_or_version")
        SCA_CVE_ID = parent_data.get("cve_number")


        # CSEC
        CSEC_PACKAGE_ID = parent_data.get("package_name_or_version")
        CSEC_CVE_ID = parent_data.get("cve_number")

        # DAST
        DAST_RESULT_URL = parent_data.get("url")

        SCAN_TYPE_SAST = "SAST"
        SCAN_TYPE_SCA = "SCA"
        SCAN_TYPE_CSEC = "CSEC"
        SCAN_TYPE_DAST = "DAST"

    # ------------- JIRA AUTOMATION PAYLOAD TESTING VARIABLES ----------------- #

        access_token_manager = AccessTokenManager(logger=log)
        access_token = access_token_manager.get_valid_token()
        cx_api_actions = CxApiActions(access_token=access_token, logger=log)
        helper = HelperFunctions()
        cx_helper = CxHelperFunctions()

        scan_type = scan_engine

        if scan_type == SCAN_TYPE_DAST:
            log.info(f"Scan Type: {scan_type}")

            # Extract result id and scan id from the URL
            result_ids = cx_helper.extract_ids_from_result_url(DAST_RESULT_URL)
            result_id = result_ids.get('result_id')
            scan_id = result_ids.get('scan_id')
            environment_id = result_ids.get('environment_id')
        
            # Check if the scan id provided by the user is the same as the scan IDs from the URL
            if SCAN_ID != result_ids.get('scan_id'):
                raise ValueError(f"Scan ID {SCAN_ID} did not match the scan ID from the URL")
            
            # Check if the scan id provided by the user really exists
            result_info = cx_api_actions.get_dast_scan_result_detailed_info(result_id, scan_id)
            if result_info is None:
                raise ValueError(f"Scan ID {SCAN_ID} is empty or does not exist")

            # JIRA to CX Mapping
            dast_triage_values_mapping = {
                "False Positive": {"state": "Not Exploitable"},
                "Downgrade to High": {"state": "Confirmed", "severity": "HIGH"},
                "Downgrade to Medium": {"state": "Confirmed", "severity": "MEDIUM"},
                "Downgrade to Low": {"state": "Confirmed", "severity": "LOW"},
            }

            cx_state, cx_severity, cx_score = _get_cx_state_severity_score(dast_triage_values_mapping, TRIAGE_STATUS)
            dast_update_response = cx_api_actions.post_dast_result_update(environment_id, [result_id], scan_id, cx_severity, cx_state, JUSTIFICATION)
            wrapped_result_id = helper.shorten_strings_middle(str(result_id))

            if dast_update_response == "OK":
                log.info(f"[DAST] Successfully updated the state and severity of Result ID: {wrapped_result_id} to State: {cx_state} Severity: {cx_severity}")
                jira_api_actions.update_successful_comment_issue(jira_issue, log, TRIAGE_UPDATE_STAGE)
            else:
                raise ValueError(f"[DAST] Failed to update the state and severity of Result ID: {wrapped_result_id}")

        else:

            scan_details = cx_api_actions.get_scan_details(SCAN_ID)
            if scan_details is None:
                raise ValueError(f"Scan ID {SCAN_ID} is empty or does not exist")
            
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

                scan_results = cx_api_actions.get_sast_results(SCAN_ID, SAST_VULN_ID)
                if scan_results is None:
                    raise ValueError(f"Scan ID {SCAN_ID} is empty or does not exist")
                
                cx_state, cx_severity, cx_score = _get_cx_state_severity_score(sast_triage_values_mapping, TRIAGE_STATUS)

                for result in scan_results.get('results'):
                    similarity_id = result.get('similarityID')
                    log.info(f"Similarity ID: {similarity_id}")
                    
                    sast_predicate_response = cx_api_actions.post_sast_predicates(similarity_id, project_id, scan_id, cx_severity, cx_state, JUSTIFICATION)
                    wrapped_similarity_id = helper.shorten_strings_middle(str(similarity_id))

                    # Expecting None 
                    if sast_predicate_response is None:
                        log.info(f"[SAST] Successfully updated the state and severity of Vulnerability ID: {wrapped_similarity_id} to State: {cx_state} Severity: {cx_severity}")
                        jira_api_actions.update_successful_comment_issue(jira_issue, log, TRIAGE_UPDATE_STAGE)
                    else:
                        raise ValueError(f"[SAST] Failed to update the state and severity of Vulnerability ID: {wrapped_similarity_id}")

            elif scan_type == SCAN_TYPE_SCA:
                log.info(f"Scan Type: {scan_type}")

                # JIRA to CX Mapping
                sca_triage_values_mapping = {
                    "False Positive": {"state": "NotExploitable", "severity": "0.0"},
                    "Downgrade to High": {"state": "Confirmed", "severity": "7"},
                    "Downgrade to Medium": {"state": "Confirmed", "severity": "4"},
                    "Downgrade to Low": {"state": "Confirmed", "severity": "0.1"},
                }

                package_name, package_version = cx_helper.set_package_and_version(SCA_PACKAGE_NAME)
                cx_state, cx_severity, cx_score = _get_cx_state_severity_score(sca_triage_values_mapping, TRIAGE_STATUS)
                # print(SCA_CVE_ID)

                sca_vuln_details = cx_api_actions.get_sca_vulnerability_details_with_CVE_graphql(scan_id, project_id, package_name, package_version, SCA_CVE_ID)
                # print(sca_vuln_details)
                cve_details = helper.get_nested(sca_vuln_details, ['data', 'vulnerabilitiesRisksByScanId', 'items'])
                # print(cve_details)
                package_repo = cve_details[0].get('packageInfo').get('packageRepository')
                package_id = cve_details[0].get('packageId')

                change_state_action = cx_api_actions.post_sca_management_of_risk(package_name, package_version, package_repo, SCA_CVE_ID, project_id, 'ChangeState', cx_state, JUSTIFICATION)
                change_score_action = cx_api_actions.post_sca_management_of_risk(package_name, package_version, package_repo, SCA_CVE_ID, project_id, 'ChangeScore', cx_severity, JUSTIFICATION)
                
                # Expecting None 
                if change_state_action is None and change_score_action is None:
                    log.info(f"[SCA] Successfully updated the state and severity of Package: {package_id} to State: {cx_state} Severity: {cx_severity}")
                    jira_api_actions.update_successful_comment_issue(jira_issue, log, TRIAGE_UPDATE_STAGE)
                else:
                    raise ValueError(f"[SCA] Failed to update the state and severity of Package: {package_id}")

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

                cx_state, cx_severity, cx_score = _get_cx_state_severity_score(csec_triage_values_mapping, TRIAGE_STATUS)

                csec_vuln_details = cx_api_actions.get_csec_vulnerability_details_graphql(scan_id, project_id, image_id, CSEC_PACKAGE_ID)
                image_vuln_details = helper.get_nested(csec_vuln_details, ['data', 'imagesVulnerabilities', 'items'])
                vuln_item_id = image_vuln_details[0].get('id')
                package_id = image_vuln_details[0].get('packageId')
                
                csec_triage_vuln_update = cx_api_actions.post_csec_vulnerability_triage_update(cx_state, cx_severity, cx_score, JUSTIFICATION, scan_id, project_id, vuln_item_id, CSEC_CVE_ID)

                if csec_triage_vuln_update is not None:
                    if csec_triage_vuln_update.get('success') is True:
                        log.info(f"[CSEC] Successfully updated the state and severity of Package: {package_id} to State: {cx_state} Severity: {cx_severity}")
                        jira_api_actions.update_successful_comment_issue(jira_issue, log, TRIAGE_UPDATE_STAGE)
                    else:
                        raise ValueError(f"[CSEC] Failed to update the state and severity of Package: {package_id}")
                else:
                    raise ValueError(f"[CSEC] Failed to update the state and severity of Package: {package_id}")
                
            else:
                log.warning(f"The {scan_type} Scan type is not supported by this workflow automation.")


    except ValueError as value_error:
        jira_api_actions.update_exception_comment_issue(jira_issue, log, value_error)
        log.error(f"Value Error: {value_error}")
        return 1
    except Exception as e:
        jira_api_actions.update_exception_comment_issue(jira_issue, log, "Unexpected Error, Please check logs")
        log.error(f"Unexpected error: {e}")
        log.error(
        "CX Update Triage failed."
        "\n\t[DEBUG GUIDE] If the issue persists, check config/field_mapping.yml for incorrect mappings "
        "\n\tbetween JIRA and the local configuration."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
