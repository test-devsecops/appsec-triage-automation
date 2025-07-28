from utils.json_file_utility import JSONFile

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