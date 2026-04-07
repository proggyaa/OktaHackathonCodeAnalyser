from flask import Blueprint, session, jsonify

from ..services.github_client import GitHubClient
from agent.auditor import mock_run_vc_audit, run_vc_audit

audit_routes = Blueprint('audit', __name__)

github_client = GitHubClient()

@audit_routes.route('/audit/<repo_name>')
def audit_repo(repo_name):
    try:
        # Get user profile for owner
        profile = github_client.get_github_profile(session)
        owner = profile.get('login', 'unknown')
        
        # Get all repo contents
        all_contents = github_client.get_all_repo_contents(session, repo_name)
        
        github_token = github_client._get_github_access_token(session)
        
        # Run audit
        result = run_vc_audit(github_token, repo_name, owner, all_contents)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "Audit failed", "details": str(e)}), 500
    