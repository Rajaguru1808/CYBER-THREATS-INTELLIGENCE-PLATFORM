"""
Central place for Flask extension instances so they can be imported
by models/controllers without causing circular imports with app/__init__.py.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access the CTI Platform.'
login_manager.login_message_category = 'warning'
