class CxApiEndpoints:

    @staticmethod
    def get_access_token(tenant_name):
        endpoint = f"/auth/realms/{tenant_name}/protocol/openid-connect/token"
        return endpoint
    
    @staticmethod
    def get_sast_results():
        endpoint = f"/api/sast-results"
        return endpoint
    
    @staticmethod
    def get_scan_details(scan_id):
        endpoint = f"/api/scans/{scan_id}"
        return endpoint
    
    @staticmethod
    def get_query_descriptions():
        endpoint = f"/api/queries/descriptions"
        return endpoint
    
    @staticmethod
    def get_vulnerability_details(cve_id):
        endpoint = f"/api/sca/vulnerabilities/v1/{cve_id}"
        return endpoint

    @staticmethod
    def get_sca_vuln_details_graphql():
        endpoint = f"/api/sca/graphql/graphql"
        return endpoint

    @staticmethod
    def get_csec_vuln_details_graphql():
        endpoint = f"/api/containers/buffet/graphql"
        return endpoint
    
    @staticmethod
    def get_dast_scan_info(scan_id):
        endpoint = f"/api/dast/scans/scan/{scan_id}"
        return endpoint
    
    @staticmethod
    def get_dast_scan_result_detailed_info(result_id, scan_id):
        endpoint = f"/api/dast/mfe-results/results/info/{result_id}/{scan_id}"
        return endpoint

    @staticmethod
    def get_dast_env_info(env_id):
        endpoint = f"/api/dast/scans/environment/{env_id}"
        return endpoint
    
    @staticmethod
    def sast_predicates():
        endpoint = f"/api/sast-results-predicates/"
        return endpoint
    
    @staticmethod
    def sca_management_of_risk():
        endpoint = f"/api/sca/management-of-risk/package-vulnerabilities"
        return endpoint
    
    @staticmethod
    def csec_vulnerability_triage_update():
        endpoint = f"/api/containers/triage/triage/vulnerability-update"
        return endpoint
    
    @staticmethod
    def dast_result_triage_update():
        endpoint = f"/api/dast/mfe-results/changelog"
        return endpoint

# -------------- Not being used ------------------

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