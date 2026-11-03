from datetime import datetime
from app.extensions import db


class ThreatEvent(db.Model):
    """A threat event, mirroring a MISP event so it can be pushed/pulled via PyMISP."""
    __tablename__ = 'threat_events'

    id = db.Column(db.Integer, primary_key=True)
    misp_event_id = db.Column(db.String(64))
    misp_uuid = db.Column(db.String(64))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    threat_level = db.Column(
        db.Enum('low', 'medium', 'high', 'critical', name='event_threat_level'),
        nullable=False, default='medium'
    )
    analysis_status = db.Column(
        db.Enum('initial', 'ongoing', 'completed', name='event_analysis_status'),
        nullable=False, default='initial'
    )
    distribution = db.Column(db.String(50), default='Your organisation only')
    org = db.Column(db.String(120))
    event_date = db.Column(db.Date)
    is_published = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    iocs = db.relationship('IOCAttribute', backref='event', lazy='dynamic', cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='event', lazy='dynamic')

    def ioc_count(self):
        return self.iocs.count()

    def to_dict(self):
        return {
            'id': self.id,
            'misp_event_id': self.misp_event_id,
            'misp_uuid': self.misp_uuid,
            'title': self.title,
            'description': self.description,
            'threat_level': self.threat_level,
            'analysis_status': self.analysis_status,
            'org': self.org,
            'event_date': self.event_date.isoformat() if self.event_date else None,
            'is_published': self.is_published,
            'ioc_count': self.ioc_count(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f'<ThreatEvent {self.title}>'
