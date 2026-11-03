from datetime import datetime
from app.extensions import db


class ActivityLog(db.Model):
    """Audit-trail entry recording a user action on the platform."""
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
    action = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='activity_logs')

    @staticmethod
    def log(user_id, action, description=None, ip_address=None):
        """Convenience helper to create + commit a log entry in one call."""
        entry = ActivityLog(
            user_id=user_id, action=action,
            description=description, ip_address=ip_address
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def to_dict(self):
        return {
            'id': self.id,
            'user': self.user.username if self.user else 'system',
            'action': self.action,
            'description': self.description,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }
