from flask import Flask
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    # Register blueprints here
    from .routes.auth import auth_routes
    from .routes.github import github_routes
    from .routes.audit import audit_routes

    app.register_blueprint(auth_routes)
    app.register_blueprint(github_routes, url_prefix='/')
    app.register_blueprint(audit_routes, url_prefix='/')

    return app