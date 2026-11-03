from datetime import datetime
from app.extensions import db


class Report(db.Model):
    """A generated PDF report (event-specific, IOC-specific, or platform summary)."""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    report_type = db.Column(
        db.Enum('event', 'ioc', 'summary', name='report_type_enum'),
        nullable=False, default='summary'
    )
    event_id = db.Column(db.Integer, db.ForeignKey('threat_events.id', ondelete='SET NULL'))
    file_path = db.Column(db.String(500), nullable=False)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'report_type': self.report_type,
            'event_id': self.event_id,
            'file_path': self.file_path,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
