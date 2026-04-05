from flask import Blueprint, redirect, session, jsonify, request, url_for

from ..services.github_client import GitHubClient

github_routes = Blueprint('github_routes', __name__)

github_client = GitHubClient()

@github_routes.route('/connect/github')
def initiate_connection():
    return github_client.initiate_connection(session)

@github_routes.route('/callback/github')
def complete_connection():
    return github_client.complete_connection(session, request)

@github_routes.route('/github/profile')
def get_github_profile():
    return github_client.get_github_profile(session)

@github_routes.route('/github/repos')
def get_github_repos():
    print("[DEBUG] Fetching GitHub repos for user...")
    return github_client.get_github_repos(session)

@github_routes.route('/github/files/<repo_name>')
def get_github_files(repo_name):
    return github_client.get_github_files(session, repo_name)

@github_routes.route('/github/full-audit/<repo_name>')
def get_all_repo_contents(repo_name):
    return github_client.get_all_repo_contents(session, repo_name)