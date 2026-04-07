import os
import asyncio
from types import SimpleNamespace
from auth0_server_python.auth_server.server_client import ServerClient
from dotenv import load_dotenv

load_dotenv()

class MemoryStateStore:
    """In-memory state store for session data (development only)"""
    def __init__(self):
        self._data = {}
    async def get(self, key, options=None):
        return self._data.get(key)
    async def set(self, key, value, options=None):
        self._data[key] = value
    async def delete(self, key, options=None):
        self._data.pop(key, None)
    async def delete_by_logout_token(self, claims, options=None):
        pass

class MemoryTransactionStore:
    """In-memory transaction store for OAuth flows (development only)"""
    def __init__(self):
        self._data = {}
    async def get(self, key, options=None):
        return self._data.get(key)
    async def set(self, key, value, options=None):
        self._data[key] = value
    async def delete(self, key, options=None):
        self._data.pop(key, None)

# Initialize stores
state_store = MemoryStateStore()
transaction_store = MemoryTransactionStore()

auth0 = ServerClient(
    domain=os.getenv('AUTH0_DOMAIN'),
    client_id=os.getenv('AUTH0_CLIENT_ID'),
    client_secret=os.getenv('AUTH0_CLIENT_SECRET'),
    secret=os.getenv('SECRET_KEY', 'dev-secret-key'),
    redirect_uri=os.getenv('AUTH0_REDIRECT_URI'),
    state_store=state_store,
    transaction_store=transaction_store,
    authorization_params={
        'scope': 'openid profile email offline_access',
        'audience': os.getenv('AUTH0_AUDIENCE', '')
    }
)

# Sync wrappers for async ServerClient methods

def get_user(store_options):
    return asyncio.run(auth0.get_user(store_options))


def start_interactive_login(params, options):
    # may be sync or async; wrap for safety
    return asyncio.run(auth0.start_interactive_login(params, options))


def complete_interactive_login(url, options):
    return asyncio.run(auth0.complete_interactive_login(url, options))


def logout(options):
    formatted_options = SimpleNamespace(**options)
    return asyncio.run(auth0.logout(formatted_options))