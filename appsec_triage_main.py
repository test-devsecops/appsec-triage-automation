import argparse
from jira_utility.jira_api_actions import JiraApiActions
from jira_utility.jira_helper_functions import JiraHelperFunctions
from utils.yml_file_utility import load_map
import appsec_triage_get_vulnerability_details as appsec_details
import appsec_triage_create_subtask as appsec_subtask
from utils.logger import Logger
import json



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

        # global variable for comment
        PULL_STAGE = True

        jira_api_actions = JiraApiActions(logger=log)


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
            jira_api_actions.populate_exception_comment_issue(jira_issue, log)
            return 1

        # Extracting data to be readable
        parent_data = {}
        for key, value in jira_issue_fields.items():
            for field_key, field_value in field_map.items():
                if field_value == key:
                    parent_data[field_key] = value

        if scan_engine == 'SAST':
            try:
                sast_jira = JiraHelperFunctions.parse_sast_input(parent_data)
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
                parent_data['github_org'] = sast_details.get('github_org')

                # parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                # log.info(f"Assigning Parent issue to group")

                # Updates the Parent task with support group 
                # jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                # log.info(f"Assigning user to parent issue")
                # Assign parent task with user
                # parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)


                sast_combined['reporter'] = jira_issue_fields.get("reporter")
                # Create subtasks
                sast_subtask = appsec_subtask.create_sast_subtask(jira_api_actions, sast_combined, field_map)
                if not sast_subtask:
                    raise Exception("Failed in creating SAST subtask")
                log.info(f"Populating Jira successful")
                jira_api_actions.update_successful_comment_issue(jira_issue, log, PULL_STAGE)
            except TypeError as e:
                log.error(f"SAST details error: {e}")
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'), error_message=str(e))
                return 1
            except Exception as e:
                log.error(f"Error during SAST processing: {e}")
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'))
                return 1
        elif scan_engine == 'SCA':
            try:
                sca_jira = JiraHelperFunctions.parse_sca_input(parent_data)
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
                parent_data['github_org'] = sca_details.get('github_org')
                # parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                # log.info(f"Assigning Parent issue to group")

                # Updates the Parent task with support group 
                # jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                # log.info(f"Assigning user to parent issue")

                # Assign parent task with user
                # parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)
                sca_combined['reporter'] = jira_issue_fields.get("reporter")

                # print(json.dumps(parent_data,indent=4))
                # Create subtasks
                sca_subtask = appsec_subtask.create_sca_subtask(jira_api_actions, sca_combined, field_map)
                if not sca_subtask:
                    raise Exception("Failed in creating SCA Subtask")
                log.info(f"Populating Jira successful")
                jira_api_actions.update_successful_comment_issue(jira_issue, log, PULL_STAGE)
            except TypeError as e:
                log.error(f"SCA details error: {e}")
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'), error_message=str(e))
                return 1
            except Exception as e:
                log.error(f"Error during SCA processing: {e}")
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'))
                return 1
        elif scan_engine == 'CSEC':
            try:
                csec_jira = JiraHelperFunctions.parse_csec_input(parent_data)
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
                parent_data['github_org'] = csec_details.get('github_org')
                # parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                # log.info(f"Assigning Parent issue to group")

                # Updates the Parent task with support group 
                # jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                # log.info(f"Assigning user to parent issue")

                # Assign parent task with user
                # parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                csec_combined['reporter'] = jira_issue_fields.get("reporter")

                # Create subtasks
                csec_subtask = appsec_subtask.create_csec_subtask(jira_api_actions, csec_combined, field_map)
                if not csec_subtask:
                    raise Exception("Failed in Creating CSEC subtask")
                
                log.info(f"Populating Jira successful")
                jira_api_actions.update_successful_comment_issue(jira_issue, log, PULL_STAGE)
            except TypeError as e:
                log.error(f"CSEC details error: {e}")
                print("PARENT DATA : ",parent_data.get('scan_id'))
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'), error_message=str(e))
                return 1
            except Exception as e:
                log.error(f"Error during CSEC processing: {e}")
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'))
                return 1
        elif scan_engine == 'DAST':
            try:
                dast_jira = JiraHelperFunctions.parse_dast_input(parent_data)
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
                parent_data['github_org'] = dast_details.get('github_org')
                # parent_data['reporter'] = jira_issue_fields.get("reporter")
                # parent_data['support_group'] = {'name' : user_type.get('support_group')}

                parenttask_to_jira_keys = {field_map.get(k, k): v for k, v in parent_data.items()}

                # Updates the Parent task with support group 
                # jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                # log.info(f"Assigning user to parent issue")

                # Assign parent task with user
                # parenttask_to_jira_keys['assignee'] = {'name' : user_type.get('assignee')}
                jira_api_actions.update_issue(parenttask_to_jira_keys, jira_issue)

                dast_combined['reporter'] = jira_issue_fields.get("reporter")

                dast_subtask = appsec_subtask.create_dast_subtask(jira_api_actions, dast_combined, field_map)
                if not dast_subtask:
                    raise Exception("Failed in creating DAST Subtask")
                log.info(f"Populating Jira successful")
                jira_api_actions.update_successful_comment_issue(jira_issue, log, PULL_STAGE)
            except TypeError as e:
                log.error(f"DAST details error: {e}")
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'), error_message=str(e))
                return 1
            except Exception as e:
                log.error(f"Error during DAST processing: {e}")
                jira_api_actions.populate_exception_comment_issue(jira_issue, log, scan_id=parent_data.get('scan_id'))
                return 1
        else:
            log.error(f"The {scan_engine} Scan type is not supported by this workflow automation.")
            return 1

    except Exception as e:
        log.error(f"Unexpected error: {e}")
        log.error(
        "Jira Populate failed."
        "[DEBUG GUIDE] If the issue persists, check config/field_mapping.yml for incorrect mappings "
        "between JIRA and the local configuration."
        )
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
