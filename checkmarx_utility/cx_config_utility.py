import os
import sys
import configparser

class Config:
    
    def __init__(self, config_file=None):
        """Load from environment variables first, fallback to config file."""
        env_token = os.getenv('CX_TOKEN')
        env_tenant_name = os.getenv('CX_TENANT_NAME')
        env_iam_url = os.getenv('CX_TENANT_IAM_URL')
        env_tenant_url = os.getenv('CX_TENANT_URL')

        if all([env_token, env_tenant_name, env_iam_url, env_tenant_url]):
            self.token = env_token
            self.tenant_name = env_tenant_name
            self.tenant_iam_url = env_iam_url
            self.tenant_url = env_tenant_url
            self.use_env = True
            return

        # Fallback to config file - Default config file will be config_dev.env
        self.use_env = False
        self.config_file = config_file or os.path.join(os.path.dirname(__file__), '..', 'config_dev.env')
        self.config = configparser.ConfigParser()
        self.config.read(self.config_file)

    def get_config(self, section='CX-PRU-NPROD'):
        """Return config values from environment or config file."""
        if self.use_env:
            return self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url

        if section not in self.config:
            print(f"Error: Section [{section}] not found in {self.config_file}")
            sys.exit(1)

        try:
            token = self.config[section]['CX_TOKEN']
            tenant_name = self.config[section]['TENANT_NAME']
            tenant_iam_url = self.config[section]['TENANT_IAM_URL']
            tenant_url = self.config[section]['TENANT_URL']
        except KeyError as e:
            print(f"Error: Missing key {e} in section [{section}] of {self.config_file}")
            sys.exit(1)

        return token, tenant_name, tenant_iam_url, tenant_url
