from utils.json_file_utility import JSONFile
from urllib.parse import urlparse, parse_qs

from datetime import datetime

import string
import re

class CxHelperFunctions:
    
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

