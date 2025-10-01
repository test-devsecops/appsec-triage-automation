# triage-workflow

## Overview

**triage-workflow** is an automation toolkit for managing application security findings across multiple scan types (SAST, SCA, CSEC, DAST) using Checkmarx and Jira integrations. It streamlines the extraction, triage, and update of vulnerability states, severities, and scores, enabling security teams to efficiently process and track findings.

## Features

- Automated extraction of vulnerability details from Checkmarx scans
- Triage and update of findings (state, severity, score) via API
- Integration with Jira for ticket creation and updates
- Support for SAST (Static Analysis), SCA (Software Composition Analysis), CSEC (Container Security), and DAST (Dynamic Analysis) workflows
- Modular utility scripts for HTTP requests, logging, configuration, and helper functions
- Configurable field mappings and user types

## How It Works

The workflow consists of Python scripts that interact with Checkmarx and Jira APIs to:
- Extract scan and vulnerability details
- Map triage statuses to Checkmarx states/severities/scores
- Update findings in Checkmarx based on triage decisions
- Optionally create or update Jira tickets for tracking and remediation

## Script Descriptions

- **appsec_triage_get_vulnerability_details.py**  
  Extracts detailed vulnerability information from Checkmarx scans (SAST, SCA, CSEC, DAST) and formats it for reporting or integration.

- **appsec_triage_update_cx_findings.py**  
  Automates the triage update process for findings, mapping Jira statuses to Checkmarx states/severities/scores and updating them via API.

- **appsec_triage_create_subtask.py**  
  (If present) Creates Jira subtasks for findings requiring remediation or further investigation.

- **appsec_triage_main.py**  
  Entry point for orchestrating the workflow, integrating extraction, triage, and ticketing.

- **checkmarx_utility/**  
  Contains modules for Checkmarx API actions, endpoint definitions, configuration, and token management.

- **jira_utility/**  
  Contains modules for Jira API actions, endpoint definitions, configuration, and helper functions.

- **utils/**  
  Shared utilities for HTTP requests, logging, exception handling, YAML/JSON file management, and helper functions.

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`
- Access to Checkmarx and Jira APIs (with credentials/configuration)
- Configuration files in `config/` for field mapping and user types

## Usage

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
2. Configure API credentials and field mappings in the `config/` directory.
3. Run the main workflow:
   ```
   python appsec_triage_main.py
   ```
4. Use individual scripts for extraction or triage updates as needed:
   ```
   python appsec_triage_get_vulnerability_details.py
   python appsec_triage_update_cx_findings.py
   ```

## Support

For issues or questions, open an issue in the repository or contact the project maintainer.

## Authors and Acknowledgments

Developed by the Ensign InfoSecurity Technology Design Team.

## License

See LICENSE file for details.

## Project Status

Actively maintained and open to contributions.
