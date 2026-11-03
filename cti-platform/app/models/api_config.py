from datetime import datetime
from app.extensions import db


class APIConfiguration(db.Model):
    """Runtime-configurable API settings for MISP / VirusTotal / OTX / AbuseIPDB."""
    __tablename__ = 'api_configuration'

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(50), unique=True, nullable=False)
    base_url = db.Column(db.String(255))
    api_key = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)
    last_checked = db.Column(db.DateTime)
    status = db.Column(
        db.Enum('connected', 'disconnected', 'unknown', name='api_status_enum'),
        default='unknown'
    )
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self, mask_key=True):
        key = self.api_key or ''
        if mask_key and key:
            key = ('*' * max(len(key) - 4, 0)) + key[-4:]
        return {
            'id': self.id,
            'service_name': self.service_name,
            'base_url': self.base_url,
            'api_key': key,
            'is_active': self.is_active,
            'status': self.status,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None,
        }
