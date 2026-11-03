"""
Application configuration.

All secrets and environment-specific values are read from environment
variables (see .env.example). Never hard-code real credentials here.
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Load variables from a .env file (if present) into the process environment
# BEFORE any os.environ.get() calls below read them. Without this, the .env
# file is silently ignored and only real OS environment variables / the
# hardcoded fallback defaults below are used.
load_dotenv(os.path.join(basedir, '.env'))


class Config:
    # --- Core Flask ---
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # --- MySQL / SQLAlchemy ---
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'Ammu')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '3306')
    DB_NAME = os.environ.get('DB_NAME', 'cti_platform')

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}

    # --- File storage ---
    REPORTS_FOLDER = os.path.join(basedir, 'reports_output')
    LOG_FOLDER = os.path.join(basedir, 'logs')

    # --- MISP (PyMISP) ---
    MISP_URL = os.environ.get('MISP_URL', 'https://localhost:8443')
    MISP_API_KEY = os.environ.get('MISP_API_KEY', '')
    MISP_VERIFY_SSL = os.environ.get('MISP_VERIFY_SSL', 'False') == 'True'

    # --- External threat intel APIs ---
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')

    # --- Pagination ---
    ITEMS_PER_PAGE = 15


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}
