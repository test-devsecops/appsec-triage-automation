class CxApiEndpoints:

    @staticmethod
    def get_access_token(tenant_name):
        endpoint = f"/auth/realms/{tenant_name}/protocol/openid-connect/token"
        return endpoint

    @staticmethod
    def get_project_last_scan():
        endpoint = "/api/projects/last-scan"
        return endpoint
    
    @staticmethod
    def get_scans():
        endpoint = "/api/scans"
        return endpoint

    @staticmethod
    def get_scan_details(scan_id):
        endpoint = f"/api/scans/{scan_id}"
        return endpoint
    
    @staticmethod
    def get_scan_summary():
        endpoint = f"/api/scan-summary"
        return endpoint

    @staticmethod
    def get_sast_results():
        endpoint = f"/api/sast-results"
        return endpoint

    @staticmethod
    def get_project_info(project_id):
        endpoint = f"/api/projects/{project_id}"
        return endpoint

    @staticmethod
    def get_application_info(application_id):
        endpoint = f"/api/applications/{application_id}"
        return endpoint

    @staticmethod
    def update_scan_tags(scan_id):
        endpoint = f"/api/scans/{scan_id}/tags"
        return endpoint