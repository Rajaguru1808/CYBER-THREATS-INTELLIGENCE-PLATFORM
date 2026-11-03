"""
Entry point for the CTI Platform Flask application.

Usage:
    python run.py                 # start the dev server
    flask --app run.py init-db    # create all tables
    flask --app run.py -db    # populate sample data (users, events, IOCs)
"""
import os
import click
from datetime import date, timedelta

from app import create_app
from app.extensions import db

app = create_app(os.environ.get('FLASK_ENV', 'development'))


@app.cli.command('init-db')
def init_db():
    """Create all database tables based on the SQLAlchemy models."""
    db.create_all()
    click.echo('Database tables created successfully.')


@app.cli.command('seed-db')
def seed_db():
    """Populate the database with demo users, events, and IOCs."""
    from app.models.user import User
    from app.models.event import ThreatEvent
    from app.models.ioc import IOCAttribute
    from app.models.api_config import APIConfiguration

    if User.query.filter_by(username='admin').first():
        click.echo('Database already seeded. Skipping.')
        return

    admin = User(username='admin', email='admin@ctiplatform.local',
                 full_name='Platform Administrator', role='admin')
    admin.set_password('Admin@123')

    analyst = User(username='analyst', email='analyst@ctiplatform.local',
                    full_name='SOC Analyst', role='analyst')
    analyst.set_password('Analyst@123')

    db.session.add_all([admin, analyst])
    db.session.commit()

    events_data = [
        ('Emotet Banking Trojan Campaign',
         'Resurgence of Emotet malspam campaign targeting financial institutions across APAC.',
         'critical', 'ongoing', admin.id),
        ('Phishing Campaign Impersonating IT Helpdesk',
         'Credential harvesting phishing emails impersonating internal IT helpdesk staff.',
         'high', 'ongoing', analyst.id),
        ('Suspicious C2 Traffic - Cobalt Strike',
         'Beaconing traffic patterns consistent with Cobalt Strike C2 framework.',
         'critical', 'initial', admin.id),
        ('Low Severity Port Scan Activity',
         'Routine reconnaissance / port scanning activity from known scanner ranges.',
         'low', 'completed', analyst.id),
        ('Ransomware IOC Bundle - LockBit',
         'IOC bundle correlated with LockBit ransomware affiliate infrastructure.',
         'critical', 'ongoing', admin.id),
    ]

    events = []
    for i, (title, desc, level, status, creator_id) in enumerate(events_data):
        e = ThreatEvent(title=title, description=desc, threat_level=level,
                         analysis_status=status, org='CTI-Platform',
                         event_date=date.today() - timedelta(days=10 - i * 2),
                         is_published=(status != 'initial'), created_by=creator_id)
        db.session.add(e)
        events.append(e)
    db.session.commit()

    iocs_data = [
        (events[0].id, 'ip', '185.220.101.45', 'critical', 90, 'misp', 'emotet,c2', True, 3),
        (events[0].id, 'domain', 'update-secure-bank.com', 'high', 80, 'otx', 'emotet,phishing-domain', True, 2),
        (events[0].id, 'hash_sha256',
         'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85',
         'critical', 95, 'virustotal', 'emotet,malware', False, 0),
        (events[1].id, 'url', 'https://it-helpdesk-secure-login.net/reset', 'high', 75, 'manual', 'phishing', False, 0),
        (events[1].id, 'email', 'support@it-helpdesk-secure-login.net', 'medium', 60, 'manual', 'phishing', False, 0),
        (events[2].id, 'ip', '45.155.204.12', 'critical', 85, 'abuseipdb', 'cobaltstrike,c2', True, 4),
        (events[3].id, 'ip', '104.244.72.115', 'low', 30, 'manual', 'scanner', False, 0),
        (events[4].id, 'hash_sha1', 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', 'critical', 92, 'virustotal', 'lockbit,ransomware', True, 5),
        (events[4].id, 'domain', 'lockbit-leaks-portal.example', 'critical', 88, 'otx', 'lockbit,leak-site', True, 2),
        (None, 'ip', '8.8.8.8', 'low', 10, 'manual', 'benign,reference', False, 0),
    ]
    for event_id, ioc_type, value, severity, score, source, tags, correlated, corr_count in iocs_data:
        db.session.add(IOCAttribute(
            event_id=event_id, ioc_type=ioc_type, ioc_value=value, severity=severity,
            confidence_score=score, source=source, tags=tags,
            is_correlated=correlated, correlation_count=corr_count,
            created_by=admin.id
        ))

    for service in ['misp', 'virustotal', 'otx', 'abuseipdb']:
        if not APIConfiguration.query.filter_by(service_name=service).first():
            db.session.add(APIConfiguration(service_name=service, is_active=False, status='unknown'))

    db.session.commit()
    click.echo('Seed data created:')
    click.echo('  Admin   -> username: admin   | password: Admin@123')
    click.echo('  Analyst -> username: analyst | password: Analyst@123')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
