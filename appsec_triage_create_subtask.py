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
                if key == 'source':
                    continue

                if key == 'attack_vector':
                    desc += f"*{key.capitalize()}* :\n"
                    i = 0
                    for atk_vector in value:
                        i = i+1
                        desc += f"{i}. {" ".join(f"*{k}*: {v}" for k, v in atk_vector.items())}\n"
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
                "justification": values.get("justification"),
                "triage_status": {"value": "False Positive"},
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
