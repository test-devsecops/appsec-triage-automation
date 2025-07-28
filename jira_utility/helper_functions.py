import string
import re

class HelperFunctions:
    
    @staticmethod
    def is_readable(text):
        # Check if all characters in a string are readable (printable)
        if all(char in string.printable for char in text):
            return True
        return False