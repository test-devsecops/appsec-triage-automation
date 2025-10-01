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
    def shorten_strings_middle(s, front=6, back=4):
        return s if len(s) <= (front + back) else s[:front] + "..." + s[-back:]

