"""Dashboard: statistics, charts, and threat feed status."""
from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from sqlalchemy import func

from app.extensions import db
from app.models.event import ThreatEvent
from app.models.ioc import IOCAttribute
from app.models.api_config import APIConfiguration

dashboard_bp = Blueprint('dashboard', __name__)


def _gather_stats():
    total_events = ThreatEvent.query.count()
    critical_events = ThreatEvent.query.filter_by(threat_level='critical').count()
    total_iocs = IOCAttribute.query.count()
    correlated_iocs = IOCAttribute.query.filter_by(is_correlated=True).count()

    severity_breakdown = dict(
        db.session.query(IOCAttribute.severity, func.count(IOCAttribute.id))
        .group_by(IOCAttribute.severity).all()
    )
    ioc_type_breakdown = dict(
        db.session.query(IOCAttribute.ioc_type, func.count(IOCAttribute.id))
        .group_by(IOCAttribute.ioc_type).all()
    )
    events_by_status = dict(
        db.session.query(ThreatEvent.analysis_status, func.count(ThreatEvent.id))
        .group_by(ThreatEvent.analysis_status).all()
    )

    recent_events = ThreatEvent.query.order_by(ThreatEvent.created_at.desc()).limit(6).all()

    feed_status = APIConfiguration.query.all()

    return {
        'total_events': total_events,
        'critical_events': critical_events,
        'total_iocs': total_iocs,
        'correlated_iocs': correlated_iocs,
        'severity_breakdown': severity_breakdown,
        'ioc_type_breakdown': ioc_type_breakdown,
        'events_by_status': events_by_status,
        'recent_events': recent_events,
        'feed_status': feed_status,
    }


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    stats = _gather_stats()
    return render_template('dashboard.html', stats=stats)


@dashboard_bp.route('/dashboard/chart-data')
@login_required
def chart_data():
    """JSON endpoint consumed by Chart.js on the dashboard page."""
    stats = _gather_stats()
    return jsonify({
        'severity_breakdown': stats['severity_breakdown'],
        'ioc_type_breakdown': stats['ioc_type_breakdown'],
        'events_by_status': stats['events_by_status'],
    })
