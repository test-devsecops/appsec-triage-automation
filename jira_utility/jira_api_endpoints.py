class JiraApiEndpoints:

    @staticmethod
    def get_queues(project_id):
        endpoint = f"/rest/servicedeskapi/servicedesk/{project_id}/queue"
        return endpoint

    @staticmethod
    def create_issue():
        endpoint = f"/rest/api/2/issue/"
        return endpoint