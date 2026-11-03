"""
Application factory for the CTI Platform.

Using the factory pattern (create_app) keeps configuration flexible for
testing/production and avoids circular imports between extensions and
blueprints.
"""
import os
from flask import Flask, render_template

from app.config import config_map
from app.extensions import db, login_manager, bcrypt
from app.utils.logger import setup_logger


def create_app(config_name=None):
    config_name = config_name or os.environ.get('FLASK_ENV', 'development')
    app = Flask(__name__)
    app.config.from_object(config_map.get(config_name, config_map['default']))

    # Ensure runtime folders exist
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['LOG_FOLDER'], exist_ok=True)

    # --- Extensions ---
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    setup_logger(app)

    # --- User loader for Flask-Login ---
    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- Register blueprints ---
    from app.controllers.auth_controller import auth_bp
    from app.controllers.dashboard_controller import dashboard_bp
    from app.controllers.ioc_controller import ioc_bp
    from app.controllers.event_controller import event_bp
    from app.controllers.report_controller import report_bp
    from app.controllers.settings_controller import settings_bp
    from app.controllers.import_controller import import_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(ioc_bp)
    app.register_blueprint(event_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(import_bp)

    # --- Error handlers ---
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception('Unhandled server error')
        return render_template('errors/500.html'), 500

    # --- Template context: expose helper for nav active-state, etc. ---
    @app.context_processor
    def inject_globals():
        return {'app_name': 'CTI Platform'}

    return app
