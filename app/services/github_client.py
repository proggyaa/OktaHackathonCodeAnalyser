import io
import os
import requests
import zipfile
from flask import redirect

class GitHubClient:
    def __init__(self):
        self.domain = os.getenv('AUTH0_DOMAIN')
        self.client_id = os.getenv('AUTH0_CLIENT_ID')
        self.client_secret = os.getenv('AUTH0_CLIENT_SECRET')

    def initiate_connection(self, session):
        user_refresh_token = session.get('refresh_token')
        if not user_refresh_token:
            return "Missing refresh token. Please log out and log back in.", 401
        token_url = f"https://{self.domain}/oauth/token"
        token_payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": user_refresh_token,
            "audience": f"https://{self.domain}/me/",
            "scope": "openid profile offline_access create:me:connected_accounts read:me:connected_accounts delete:me:connected_accounts"
        }
        token_res = requests.post(token_url, data=token_payload)
        if token_res.status_code != 200:
            return f"Failed to get My Account token: {token_res.text}", 400
        my_account_token = token_res.json().get("access_token")
        connect_url = f"https://{self.domain}/me/v1/connected-accounts/connect"
        connect_headers = {"Authorization": f"Bearer {my_account_token}"}
        connect_payload = {
            "connection": "github",
            "redirect_uri": "http://localhost:5000/callback/github",
            "state": "random_secure_state_12345",
            "scopes": ["offline_access"]
        }
        connect_res = requests.post(connect_url, json=connect_payload, headers=connect_headers)
        connect_data = connect_res.json()
        auth_session = connect_data.get("auth_session")
        session["auth_session"] = auth_session
        connect_uri = connect_data.get('connect_uri')
        connect_params = connect_data.get('connect_params', {})
        ticket = connect_params.get('ticket')
        return redirect(f"{connect_uri}?ticket={ticket}")

    def _get_github_access_token(self, session):
        """Helper method to exchange Auth0 refresh token for GitHub access token."""
        user_refresh_token = session.get('refresh_token')
        if not user_refresh_token:
            return None
        
        token_url = f"https://{self.domain}/oauth/token"
        exchange_payload = {
            "connection": "github",
            "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
            "subject_token": user_refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        res = requests.post(token_url, data=exchange_payload)
        if res.status_code != 200:
            return None
        return res.json().get("access_token")

    def complete_connection(self, session, request):
        connect_code = request.args.get("connect_code")
        saved_auth_session = session.get("auth_session")
        if not connect_code or not saved_auth_session:
            return "Missing code or session", 400
        user_refresh_token = session.get('refresh_token')
        if not user_refresh_token:
            return "Missing refresh token. Please log out and log back in.", 401
        token_url = f"https://{self.domain}/oauth/token"
        token_payload = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": user_refresh_token,
            "audience": f"https://{self.domain}/me/"
        }
        token_res = requests.post(token_url, data=token_payload)
        my_account_token = token_res.json().get("access_token")
        complete_url = f"https://{self.domain}/me/v1/connected-accounts/complete"
        complete_headers = {"Authorization": f"Bearer {my_account_token}"}
        complete_payload = {
            "auth_session": saved_auth_session,
            "connect_code": connect_code,
            "redirect_uri": "http://localhost:5000/callback/github"
        }
        complete_res = requests.post(complete_url, json=complete_payload, headers=complete_headers)
        if complete_res.status_code == 201:
            session.pop("auth_session", None)
            return redirect("/profile")
        else:
            return {"error": "Linking failed", "details": complete_res.json()}, 400

    def get_github_profile(self, session):
        user_refresh_token = session.get('refresh_token')
        if not user_refresh_token:
            return "Not logged in. Please log in first.", 401
        token_url = f"https://{self.domain}/oauth/token"
        exchange_payload = {
            "connection": "github",
            "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
            "subject_token": user_refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        res = requests.post(token_url, data=exchange_payload)
        if res.status_code != 200:
            return f"Exchange failed: {res.text}", 400
        github_access_token = res.json().get("access_token")
        github_api_url = "https://api.github.com/user"
        headers = {"Authorization": f"token {github_access_token}", "Accept": "application/vnd.github.v3+json"}
        profile_res = requests.get(github_api_url, headers=headers)
        return profile_res.json()

    def get_github_repos(self, session):
        user_refresh_token = session.get('refresh_token')
        token_url = f"https://{self.domain}/oauth/token"
        exchange_payload = {
            "connection": "github",
            "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
            "subject_token": user_refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        res = requests.post(token_url, data=exchange_payload)
        github_access_token = res.json().get("access_token")
        headers = {"Authorization": f"token {github_access_token}", "Accept": "application/vnd.github.v3+json"}
        repo_res = requests.get("https://api.github.com/user/repos?sort=updated&per_page=5", headers=headers)
        return repo_res.json()

    def get_github_files(self, session, repo_name):
        user_refresh_token = session.get('refresh_token')
        token_url = f"https://{self.domain}/oauth/token"
        exchange_payload = {
            "connection": "github",
            "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
            "subject_token": user_refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        res = requests.post(token_url, data=exchange_payload)
        github_access_token = res.json().get("access_token")
        user_res = requests.get("https://api.github.com/user", headers={"Authorization": f"token {github_access_token}"})
        username = user_res.json().get("login")
        tree_url = f"https://api.github.com/repos/{username}/{repo_name}/git/trees/main?recursive=1"
        headers = {"Authorization": f"token {github_access_token}", "Accept": "application/vnd.github.v3+json"}
        tree_res = requests.get(tree_url, headers=headers)
        if tree_res.status_code == 404:
            tree_url = tree_url.replace('/main?', '/master?')
            tree_res = requests.get(tree_url, headers=headers)
        return tree_res.json()

    def get_all_repo_contents(self, session, repo_name):
        # 1. Get token and username (Keep your existing logic for this)
        github_access_token = self._get_github_access_token(session)
        user_res = requests.get("https://api.github.com/user", headers={"Authorization": f"token {github_access_token}"})
        username = user_res.json().get("login")

        # --- OPTIMIZATION: Single-Request Zip Archive Fetch ---
        zip_url = f"https://api.github.com/repos/{username}/{repo_name}/zipball/main"
        headers = {
            "Authorization": f"token {github_access_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        res = requests.get(zip_url, headers=headers)

        if res.status_code == 404:
            # Fallback to master if main branch doesn't exist
            zip_url = zip_url.replace('/main', '/master')
            res = requests.get(zip_url, headers=headers)

        if res.status_code != 200:
            return {}

        all_contents = {}
        valid_extensions = ('.py', '.js', '.ts', '.jsx', '.tsx')

        # 2. Extract strictly in memory
        with zipfile.ZipFile(io.BytesIO(res.content)) as z:
            for info in z.infolist():
                if info.is_dir() or not info.filename.endswith(valid_extensions):
                    continue
                
                try:
                    # Read bytes and decode to string, ignoring broken characters
                    content = z.read(info.filename).decode('utf-8', errors='ignore')
                    
                    # Optional: GitHub zipballs prefix files with "owner-repo-commitHash/".
                    # You can split on the first "/" to get the raw repository path.
                    clean_path = info.filename.split("/", 1)[-1] 
                    
                    all_contents[clean_path] = content
                except Exception as e:
                    throwable_error = f"Error processing {info.filename}: {str(e)}"
        return all_contents