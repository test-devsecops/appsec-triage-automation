from jira_utility.jira_api_actions import JiraApiActions
import json
from utils.logger import Logger

def create_sast_subtask(api_action: JiraApiActions, data: dict, field_mapping: dict):
    log = Logger("appsec_triage")
    try:
        log.info(f"Creating subtasks")
        main_payload = {
            "lbu": data.get("lbu"),
            "project_name": data.get("project_name"),
            "branch_name": data.get("branch_name"),
            "scan_id": data.get("scan_id"),
            "parent": {
                "key": data.get("jira_issue")
            },
        }

        for values in data.get("vulnerability"):
            desc = ""
            for key, value in values.get("vulnerability_description").items():
                # removed source because it consist of "code" which was detected by the WAF.
                if value in ("", []):
                    continue

                if key == 'source':
                    continue

                if key == 'attack_vector':
                    desc += f"*{key.capitalize()}* :\n"
                    i = 0
                    for atk_vector in value:
                        i = i+1
                        # desc += f"{i}. {" ".join(f"*{k}*: {v}" for k, v in atk_vector.items())}\n"
                        desc += f'{i}. {" | ".join(f"{k}: {v}" for k, v in atk_vector.items() if v not in ("", []))}\r\n'
                elif key == 'description':
                    desc += f"{value}\r"
                elif key == 'recommendations':
                    desc += f"*{key.capitalize()}* :\r{value}\r"
                else:
                    desc += f"*{key.capitalize()}* : {value}\r"

            vuln_payload = {
                "summary": f"SAST | {values.get('vulnerability_name')}",
                "vulnerability": values.get('vulnerability_id'),
                "vulnerability_name": values.get('vulnerability_name'),
                "justification": "Please Input Justification",
                "triage_status": {"value": "Please select value"},
                "description": desc
            }

            payload = main_payload | vuln_payload

            # This changes the keys to become jira customfields keys
            subtask_to_jira_keys = {field_mapping.get(k, k): v for k, v in payload.items()}

            try:
                api_action.create_subtask(subtask_to_jira_keys)
            except Exception as e:
                log.error(f"Failed to create subtask for vulnerability {values.get('vulnerability_id')}: {e}")

    except Exception as e:
        log.error(f"Error in create_sast_subtask: {e}")


def create_sca_subtask(api_action: JiraApiActions, data: dict, field_mapping: dict):
    log = Logger("appsec_triage")
    try:
        log.info(f"Creating subtasks")
        main_payload = {
            "lbu": data.get("lbu"),
            "project_name": data.get("project_name"),
            "branch_name": data.get("branch_name"),
            "scan_id": data.get("scan_id"),
            "parent": {
                "key": data.get("jira_issue")
            },
        }

        for values in data.get("package"):
            desc = ""
            for key, value in values.get("cve_description").items():
                if value in ("", []):
                    continue

                if key == 'references':
                    desc += f"{key.capitalize()} :\r\n"
                    i = 0
                    for atk_vector in value:
                        i = i+1
                        # desc += f"{i}. {" ".join(f"{k}: {v}" for k, v in atk_vector.items())}\r\n"
                        desc += f'{i}. {" | ".join(f"{k}: {v}" for k, v in atk_vector.items() if v not in ("", []))}\r\n'
                elif key == 'description':
                    desc += f"{value}\r\n"
                else:
                    desc += f"{key.capitalize()} : {value}\r\n"

            vuln_payload = {
                "summary": f"SCA | {values.get('cve_number')}",
                "cve_number": values.get('cve_number'),
                "cvss_score": str(values.get('cvss_score')),
                "cve_description": desc,
                "epss_score" : str(values.get('epss_score')),
                "justification" : "Please Input Justification",
                "triage_status": {"value": "Please select value"},
                # "description": values.get('cve_number')
            }

            payload = main_payload | vuln_payload

            # This changes the keys to become jira customfields keys
            subtask_to_jira_keys = {field_mapping.get(k, k): v for k, v in payload.items()}

            try:
                api_action.create_subtask(subtask_to_jira_keys)
            except Exception as e:
                log.error(f"Failed to create subtask for cve {values.get('cve_number')}: {e}")

    except Exception as e:
        log.error(f"Error in create_sast_subtask: {e}")

def create_csec_subtask(api_action: JiraApiActions, data: dict, field_mapping: dict):
    log = Logger("appsec_triage")
    try:
        log.info(f"Creating subtasks")
        main_payload = {
            "lbu": data.get("lbu"),
            "project_name": data.get("project_name"),
            "branch_name": data.get("branch_name"),
            "scan_id": data.get("scan_id"),
            "parent": {
                "key": data.get("jira_issue")
            },
        }

        package_info = data.get("package")

        for values in data.get("package").get("cves"):
            desc = ""
            for key, value in values.get("cve_description").items():
                if value in ("", []):
                    continue

                if key == 'references':
                    desc += f"{key.capitalize()} :\r\n"
                    i = 0
                    for atk_vector in value:
                        i = i+1
                        # desc += f"{i}. {" ".join(f"{k}: {v}" for k, v in atk_vector.items())}\r\n"
                        desc += f'{i}. {" | ".join(f"{k}: {v}" for k, v in atk_vector.items() if v not in ("", []))}\r\n'
                elif key == 'description':
                    desc += f"{value}\r\n"
                else:
                    desc += f"{key.capitalize()} : {value}\r\n"

            vuln_payload = {
                "summary": f"CSEC | {values.get('cve_number')}",
                "package_name_or_version" : package_info.get('package_name'),
                "image_name" : package_info.get("image_name"),
                "cve_number": values.get('cve_number'),
                "cvss_score": str(values.get('cvss_score')),
                "cve_description": desc,
                "epss_score" : str(values.get('epss_score')),
                "justification" : "Please Input Justification",
                "triage_status": {"value": "Please select value"},
            }

            payload = main_payload | vuln_payload

            # print(payload)

            # This changes the keys to become jira customfields keys
            subtask_to_jira_keys = {field_mapping.get(k, k): v for k, v in payload.items()}

            try:
                api_action.create_subtask(subtask_to_jira_keys)
            except Exception as e:
                log.error(f"Failed to create subtask for cve {values.get('cve_number')}: {e}")

    except Exception as e:
        log.error(f"Error in create_csec_subtask: {e}")

def create_dast_subtask(api_action: JiraApiActions, data: dict, field_mapping: dict):
    log = Logger("appsec_triage")
    try:
        log.info(f"Creating subtasks")
        main_payload = {
            "lbu": data.get("lbu"),
            "environment_name": data.get("env_name"),
            "branch_name": data.get("branch_name"),
            "scan_id": data.get("scan_id"),
            "parent": {
                "key": data.get("jira_issue")
            },
        }

        for values in data.get("findings"):
            desc = ""
            # print(json.dumps(values.get('result_description')))

            for key, value in values.get("result_description").items():
                if value in ("", []):
                    continue

                if key == 'attack' or key == 'path':
                    continue

                if key == 'solution':
                    desc += f"*{key.capitalize()}* :\r\n {value}\r\n"

                elif key == 'description':
                    desc += f"{value}\r\n"
                else:
                    desc += f"*{key.capitalize()}* : {value}\r\n"

            vuln_payload = {
                "summary": f"DAST | {values.get('result_category')}",
                "url" : values.get("vulnerability_url"),
                "description" : desc,
                "justification" : "Please Input justification",
                # will need to change to use from data itself, not hardcoded
                "triage_status": {"value": "Please select value"},
                "severity" : values.get("result_description").get("severity")
            }

            payload = main_payload | vuln_payload

            # This changes the keys to become jira customfields keys
            subtask_to_jira_keys = {field_mapping.get(k, k): v for k, v in payload.items()}

            try:
                api_action.create_subtask(subtask_to_jira_keys)
            except Exception as e:
                log.error(f"Failed to create subtask for cve {values.get('cve_number')}: {e}")

    except Exception as e:
        log.error(f"Error in create_csec_subtask: {e}")