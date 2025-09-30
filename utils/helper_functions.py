from utils.json_file_utility import JSONFile
from urllib.parse import urlparse, parse_qs

from datetime import datetime

import string
import re

class HelperFunctions:
    
    @staticmethod
    def get_today_date_yyyymmdd():
        return datetime.today().strftime('%Y%m%d')

    @staticmethod
    def get_lbu_name_simple(app_name):
        """
        Extracts the LBU name directly after 'pru-' in the given project_name.
        Does not validate against any JSON list.
        """
        match = re.search(r'^pru-([\w]+)', app_name, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        
        return "Pru"

    @staticmethod
    def is_readable(text):
        # Check if all characters in a string are readable (printable)
        if all(char in string.printable for char in text):
            return True
        return False
    
    @staticmethod
    def get_nested(data, keys, default=None):
        """
        Safely access nested dictionary keys.
        
        :param data: The dictionary to traverse.
        :param keys: A list of keys representing the path.
        :param default: Value to return if any key is missing.
        :return: The value at the nested key or default.
        """
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, default)
            else:
                return default
        return data
    
    @staticmethod
    def set_package_and_version(package_version: str) -> tuple[str, str]:
        """
        Splits a package string into name and version for SCA.
        Example: 'multer 1.4.5-lts.2' -> ('multer', '1.4.5-lts.2')
        """
        name, version = package_version.rsplit(" ", 1)
        return name, version
    
    @staticmethod
    def extract_ids_from_result_url(result_url):
        """
        Extracts environment_id, scan_id, and result_id from a Checkmarx DAST results URL.
        """
        parsed = urlparse(result_url)
        # Path: /applicationsAndProjects/environments/{environment_id}/{scan_id}
        path_parts = parsed.path.split('/')
        # Find the index of 'environments'
        try:
            env_idx = path_parts.index('environments')
            environment_id = path_parts[env_idx + 1]
            scan_id = path_parts[env_idx + 2]
        except (ValueError, IndexError):
            environment_id = None
            scan_id = None

        # Get resultId from query string
        query_params = parse_qs(parsed.query)
        result_id = query_params.get('resultId', [None])[0]

        return {
            "environment_id": environment_id,
            "scan_id": scan_id,
            "result_id": result_id
        }

    @staticmethod
    def shorten_strings_middle(s, front=6, back=4):
        return s if len(s) <= (front + back) else s[:front] + "..." + s[-back:]

