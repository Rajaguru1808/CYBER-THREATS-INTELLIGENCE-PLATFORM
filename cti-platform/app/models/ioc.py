from datetime import datetime
from app.extensions import db


class IOCAttribute(db.Model):
    """An Indicator of Compromise (IP, domain, URL, email, or file hash)."""
    __tablename__ = 'ioc_attributes'

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('threat_events.id', ondelete='CASCADE'))
    ioc_type = db.Column(
        db.Enum('ip', 'domain', 'url', 'email', 'hash_md5', 'hash_sha1', 'hash_sha256',
                name='ioc_type_enum'),
        nullable=False
    )
    ioc_value = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(100), default='Network activity')
    severity = db.Column(
        db.Enum('low', 'medium', 'high', 'critical', name='ioc_severity'),
        nullable=False, default='medium'
    )
    confidence_score = db.Column(db.Integer, default=50)
    source = db.Column(db.String(100), default='manual')
    tags = db.Column(db.String(500))
    is_correlated = db.Column(db.Boolean, default=False)
    correlation_count = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def tag_list(self):
        return [t.strip() for t in (self.tags or '').split(',') if t.strip()]

    def to_dict(self):
        return {
            'id': self.id,
            'event_id': self.event_id,
            'ioc_type': self.ioc_type,
            'ioc_value': self.ioc_value,
            'category': self.category,
            'severity': self.severity,
            'confidence_score': self.confidence_score,
            'source': self.source,
            'tags': self.tag_list(),
            'is_correlated': self.is_correlated,
            'correlation_count': self.correlation_count,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
        }

    def __repr__(self):
        return f'<IOC {self.ioc_type}:{self.ioc_value}>'
