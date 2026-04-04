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

@auth_routes.route('/logout')
def logout():
    options = {
        "return_to": url_for("auth_routes.index", _external=True),
        "state": session.get("user").get("state") if session.get("user") else "logout_state"
    }
    print(f"[DEBUG] Logging out with g.store_options: {options}")
    logout_url = auth0_logout(options)
    
    return redirect(logout_url)