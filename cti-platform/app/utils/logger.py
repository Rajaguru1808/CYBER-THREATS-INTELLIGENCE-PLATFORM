"""Application-wide file logger (separate from the DB activity_logs audit trail)."""
import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger(app):
    log_folder = app.config['LOG_FOLDER']
    os.makedirs(log_folder, exist_ok=True)
    log_file = os.path.join(log_folder, 'cti_platform.log')

    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Logger initialized.')
    return app.logger
