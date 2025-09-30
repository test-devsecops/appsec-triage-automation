import os
import sys
import configparser

class Config:
    
    def __init__(self, config_file=None):
        """Load from environment variables first, fallback to config file."""
        env_token = os.getenv('JIRA_PAT')
        env_project_id = os.getenv('JIRA_PROJECT_ID')
        env_jira_url = os.getenv('JIRA_URL')
        env_issuetype_id= os.getenv('ISSUETYPE_ID')

        if all([env_token, env_project_id, env_jira_url]):
            self.token = env_token
            self.project_id = env_project_id
            self.jira_url = env_jira_url
            self.issuetype_id = env_issuetype_id
            self.use_env = True
            return

        # Fallback to config file - Default config file will be config_dev.env
        self.use_env = False
        self.config_file = config_file or os.path.join(os.path.dirname(__file__), '..', 'config_dev.env')
        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)

    def get_config(self, section='JIRA-EIS'):
        """Return config values from environment or config file."""
        if self.use_env:
            return self.token, self.project_id, self.jira_url, self.issuetype_id

        if section not in self.config:
            print(f"Error: Section [{section}] not found in {self.config_file}")
            sys.exit(1)

        try:
            token = self.config[section]['JIRA_PAT']
            project_id = self.config[section]['JIRA_PROJECT_ID']
            jira_url = self.config[section]['JIRA_URL']
            issuetype_id = self.config[section]['ISSUETYPE_ID']
        except KeyError as e:
            print(f"JIRA Config Error: Missing key {e} in section [{section}] of {self.config_file}")
            sys.exit(1)

        return token, project_id, jira_url, issuetype_id
