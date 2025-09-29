import argparse
from jira_utility.jira_api_actions import JiraApiActions
from jira_utility.helper_functions import HelperFunctions
from utils.yml_file_utility import load_map
import appsec_triage_get_vulnerability_details as appsec_details
import appsec_triage_create_subtask as appsec_subtask
from utils.logger import Logger
import json


def _exception_update_description(jira_api_actions : JiraApiActions, jira_issue: str, log: Logger):
    description = "[ERROR] Please check Github Actions for error message."
    added_payload = {
        'description' : description
    }
    try:
        jira_api_actions.update_issue(added_payload,jira_issue)
    except Exception as e:
        log.error(f"Failed to update issue with error : {e}")

    pass

def main():
    log = Logger("appsec_triage")
    try:
        parser = argparse.ArgumentParser(
            description="AppSec Triage Script"
        )
        parser.add_argument("jira_issue", help="Jira Issue Key e.g. ABC-123")
        parser.add_argument("scan_engine_type", help="Scan Engine Types e.g SAST, SCA, CSEC, DAST")
        # parser.add_argument("reference_num", nargs="?", default="", help="Reference Number for debugging purposes (optional, used by GitHub Actions)")
        args = parser.parse_args()
        jira_issue = args.jira_issue
        scan_engine = args.scan_engine_type
        # reference_number = args.reference_num

        print(f"Jira issue: {jira_issue}")
        print(f"Scan Engine: {scan_engine}")
        # print(f"Ref Number: {reference_number if reference_number else 'N/A'}")

        jira_config_environment = "JIRA-EIS"
        jira_api_actions = JiraApiActions(jira_config_environment)

        try:
            jira_issue_data = jira_api_actions.get_issue(jira_issue)
            jira_issue_fields = jira_issue_data.get("fields")
            jira_issue_fields = HelperFunctions.remove_all_null_key_values(jira_issue_fields)
        except Exception as e:
            log.error(f"Failed to fetch or process Jira issue data: {e}")
            _exception_update_description(jira_api_actions,jira_issue,log)
            return 1

        try:
            field_map = load_map('config/field_mapping.yml',parent_field='fields')
            user_type = load_map('config/user_type.yml',parent_field='user_type')
        except Exception as e:
            log.error(f"Failed to load yaml mapping: {e}")
            _exception_update_description(jira_api_actions,jira_issue,log)
            return 1

        # Extracting data to be readable
        parent_data = {}
        for key, value in jira_issue_fields.items():
            for field_key, field_value in field_map.items():
                if field_value == key:
                    parent_data[field_key] = value

        if scan_engine == 'SAST':
            try:
                sast_jira = HelperFunctions.parse_sast_input(parent_data)
                sast_details = appsec_details.get_vuln_details(
                    input_scan_id=sast_jira.get('scan_id'),
                    input_vuln_ids=sast_jira.get('vuln_ids'),
                    scan_type=scan_engine,
                    input_package_name=""
                )

                sast_details['scan_engine'] = scan_engine
                sast_details['jira_issue'] = jira_issue

                sast_combined = sast_jira | sast_details
                parent_data['branch_name'] = sast_details.get("branch_name")
                parent_data['project_name'] = sast_details.get("project_name")
                parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                log.info(f"Assigning Parent issue to group")

                # Updates the Parent task with support group 
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                log.info(f"Assigning user to parent issue")
                # Assign parent task with user
                parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                # Create subtasks
                appsec_subtask.create_sast_subtask(jira_api_actions, sast_combined, field_map)
                log.info(f"Populating Jira successful")
            except Exception as e:
                log.error(f"Error during SAST processing: {e}")
                _exception_update_description(jira_api_actions,jira_issue,log)
                return 1
        elif scan_engine == 'SCA':
            try:
                sca_jira = HelperFunctions.parse_sca_input(parent_data)
                sca_details = appsec_details.get_vuln_details(
                    input_scan_id=sca_jira.get('scan_id'),
                    input_vuln_ids="",
                    scan_type=scan_engine,
                    input_package_name=sca_jira.get("package_name_or_version")
                )

                sca_details['scan_engine'] = scan_engine
                sca_details['jira_issue'] = jira_issue

                sca_combined = sca_jira | sca_details
                parent_data['branch_name'] = sca_details.get("branch_name")
                parent_data['project_name'] = sca_details.get("project_name")
                parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                log.info(f"Assigning Parent issue to group")

                # Updates the Parent task with support group 
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                log.info(f"Assigning user to parent issue")

                # Assign parent task with user
                parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                # print(json.dumps(parent_data,indent=4))
                # Create subtasks
                appsec_subtask.create_sca_subtask(jira_api_actions, sca_combined, field_map)

            except Exception as e:
                log.error(f"Error during SCA processing: {e}")
                _exception_update_description(jira_api_actions,jira_issue,log)
                return 1
        elif scan_engine == 'CSEC':
            try:
                csec_jira = HelperFunctions.parse_csec_input(parent_data)
                csec_details = appsec_details.get_vuln_details(
                    input_scan_id=csec_jira.get('scan_id'),
                    input_vuln_ids="",
                    scan_type=scan_engine,
                    input_package_name=csec_jira.get("package_name_or_version")
                )

                csec_details['scan_engine'] = scan_engine
                csec_details['jira_issue'] = jira_issue

                csec_combined = csec_jira | csec_details
                parent_data['branch_name'] = csec_details.get("branch_name")
                parent_data['project_name'] = csec_details.get("project_name")
                parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                log.info(f"Assigning Parent issue to group")

                # Updates the Parent task with support group 
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                log.info(f"Assigning user to parent issue")

                # Assign parent task with user
                parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                # Create subtasks
                appsec_subtask.create_csec_subtask(jira_api_actions, csec_combined, field_map)
            except Exception as e:
                log.error(f"Error during CSEC processing: {e}")
                _exception_update_description(jira_api_actions,jira_issue,log)
                return 1
        elif scan_engine == 'DAST':
            try:
                dast_jira = HelperFunctions.parse_dast_input(parent_data)
                dast_details = appsec_details.get_vuln_details(
                    input_scan_id=dast_jira.get('scan_id'),
                    input_vuln_ids="",
                    scan_type=scan_engine,
                    input_package_name="",
                    input_urls=dast_jira.get("urls")
                )

                dast_details['scan_engine'] = scan_engine
                dast_details['jira_issue'] = jira_issue

                dast_combined = dast_jira | dast_details
                parent_data['branch_name'] = dast_details.get("branch_name")
                parent_data['project_name'] = dast_details.get("project_name")
                parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                # Updates the Parent task with support group 
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                log.info(f"Assigning user to parent issue")

                # Assign parent task with user
                parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                appsec_subtask.create_dast_subtask(jira_api_actions, dast_combined, field_map)
            except Exception as e:
                log.error(f"Error during DAST processing: {e}")
                _exception_update_description(jira_api_actions,jira_issue,log)
                return 1
        else:
            log.error(f"The {scan_engine} Scan type is not supported by this workflow automation.")
            return 1

    except Exception as e:
        log.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
