class JiraParsingUtility:

    @staticmethod
    def parse_sast_input(data: dict):
        try:
            return data
        except Exception as e:
            print(f"Error in parsing SAST: {e}")
            return None

    @staticmethod
    def parse_sca_input(data: dict):
        try:
            return data
        except Exception as e:
            print(f"Error in parsing SCA: {e}")
            return None

    @staticmethod
    def parse_csec_input(data: dict):
        try:
            return data
        except Exception as e:
            print(f"Error in parsing CSEC: {e}")
            return None

    @staticmethod
    def parse_dast_input(data: dict):
        try:
            return data
        except Exception as e:
            print(f"Error in parsing DAST: {e}")
            return None
