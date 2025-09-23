import argparse
from jira_utility.jira_parsing_utility import JiraParsingUtility

def main():
    parser = argparse.ArgumentParser(
        description="AppSec Triage Script"
    )
    parser.add_argument("jira_issue", help="Jira Issue Key e.g. ABC-123")
    parser.add_argument("scan_engine_type", help="Scan Engine Types e.g SAST, SCA, CSEC, DAST")
    args = parser.parse_args()

    print(f"Jira issue: {args.jira_issue}")
    print(f"Scan Engine: {args.scan_engine_type}")

if __name__ == "__main__":
    main()
