from flask import Blueprint, redirect, session, render_template, request, url_for, g

from ..services.auth0_client import get_user, start_interactive_login, complete_interactive_login, logout as auth0_logout

# Blueprint for authentication routes
auth_routes = Blueprint('auth_routes', __name__)

@auth_routes.before_app_request
def store_request_response():
    """Make request/response available for Auth0 SDK"""
    g.store_options = {"request": request}

@auth_routes.route('/')
def index():
    user = get_user(g.store_options)
    return render_template('index.html', user=user)

@auth_routes.route('/login')
def login():
    authorization_url = start_interactive_login({}, {"authorization_params": {"scope": "openid profile offline_access"}, **g.store_options})
    return redirect(authorization_url)

@auth_routes.route('/callback')
def callback():
    try:
        result = complete_interactive_login(str(request.url), g.store_options)
        refresh_token = None
        if isinstance(result, dict):
            state_data = result.get('state_data', {})
            refresh_token = state_data.get('refresh_token')
            if not refresh_token:
                refresh_token = result.get('refresh_token')
        if refresh_token:
            session['refresh_token'] = refresh_token
        return redirect(url_for('auth_routes.index'))
    except Exception as e:
        return f"Authentication error: {str(e)}", 400

@auth_routes.route('/profile')
def profile():
    user = get_user(g.store_options)
    if not user:
        return redirect(url_for('auth_routes.login'))
    return render_template('profile.html', user=user)

@auth_routes.route('/audit')
def audit_view():
    """Step 2: The Analysis Terminal"""
    user = get_user(g.store_options)
    if not user:
        return redirect(url_for('auth_routes.login'))
    # This renders the Repository Input and 3D Graph
    return render_template('audit.html', user=user)

@auth_routes.route('/logout')
def logout():
    # 1. Clear the local Flask session immediately
    session.clear()

    # 2. Build the explicit return URL
    # Ensure this EXACT string is in your Auth0 "Allowed Logout URLs"
    return_to = url_for("auth_routes.index", _external=True)
    
    # 3. Call the logout service
    # We pass the return_to explicitly to ensure the SDK builds the URL correctly
    try:
        # If your auth0_client.logout takes a dict, ensure it maps to 'returnTo'
        logout_url = auth0_logout({"return_to": return_to})
        
        print(f"[DEBUG] Redirecting to Auth0 Logout: {logout_url}")
        return redirect(logout_url)
        
    except Exception as e:
        print(f"[ERROR] Logout URL generation failed: {e}")
        # Fallback to index if the SDK fails
        return redirect(url_for("auth_routes.index"))