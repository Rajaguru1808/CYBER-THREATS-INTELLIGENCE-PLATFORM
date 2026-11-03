"""Threat Event management: CRUD + create/update linked MISP events."""
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user

from app.extensions import db
from app.models.event import ThreatEvent
from app.models.ioc import IOCAttribute
from app.models.activity_log import ActivityLog
from app.services.misp_service import MISPService
from app.models.api_config import APIConfiguration

event_bp = Blueprint('event', __name__)


def _misp_client():
    """Build a MISPService using the URL/key saved on Settings > API
    Configuration (DB) instead of only the environment variable."""
    cfg = APIConfiguration.query.filter_by(service_name='misp').first()
    return MISPService(
        url=cfg.base_url if cfg and cfg.base_url else None,
        api_key=cfg.api_key if cfg and cfg.api_key else None,
    )


@event_bp.route('/events')
@login_required
def list_events():
    page = request.args.get('page', 1, type=int)
    threat_level = request.args.get('threat_level', '')
    status = request.args.get('status', '')

    query = ThreatEvent.query
    if threat_level:
        query = query.filter_by(threat_level=threat_level)
    if status:
        query = query.filter_by(analysis_status=status)

    pagination = query.order_by(ThreatEvent.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    return render_template('event_management.html', pagination=pagination,
                            events=pagination.items,
                            filters={'threat_level': threat_level, 'status': status})


@event_bp.route('/events/<int:event_id>')
@login_required
def view_event(event_id):
    event = ThreatEvent.query.get_or_404(event_id)
    iocs = event.iocs.order_by(IOCAttribute.created_at.desc()).all()
    return render_template('event_detail.html', event=event, iocs=iocs)


@event_bp.route('/events/create', methods=['POST'])
@login_required
def create_event():
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    threat_level = request.form.get('threat_level', 'medium')
    analysis_status = request.form.get('analysis_status', 'initial')
    org = request.form.get('org', '').strip()
    event_date = request.form.get('event_date') or None
    push_to_misp = request.form.get('push_to_misp') == 'on'

    if not title:
        flash('Event title is required.', 'danger')
        return redirect(url_for('event.list_events'))

    event = ThreatEvent(
        title=title, description=description, threat_level=threat_level,
        analysis_status=analysis_status, org=org,
        # Default to today if the user didn't pick a date in the form.
        event_date=datetime.strptime(event_date, '%Y-%m-%d').date() if event_date else datetime.utcnow().date(),
        created_by=current_user.id
    )
    db.session.add(event)
    db.session.commit()

    if push_to_misp:
        try:
            misp = _misp_client()
            result = misp.create_event(title, description, threat_level)
            if isinstance(result, dict) and 'Event' in result:
                event.misp_event_id = result['Event'].get('id')
                event.misp_uuid = result['Event'].get('uuid')
                db.session.commit()
                flash('Event created and pushed to MISP.', 'success')
            else:
                flash('Event saved locally, but MISP push returned unexpected response.', 'warning')
        except Exception as exc:  # noqa: BLE001
            flash(f'Event saved locally, but MISP push failed: {exc}', 'warning')
    else:
        flash('Threat event created.', 'success')

    ActivityLog.log(current_user.id, 'CREATE_EVENT', f'Created event: {title}', request.remote_addr)
    return redirect(url_for('event.list_events'))


@event_bp.route('/events/<int:event_id>/update', methods=['POST'])
@login_required
def update_event(event_id):
    event = ThreatEvent.query.get_or_404(event_id)
    event.title = request.form.get('title', event.title).strip()
    event.description = request.form.get('description', event.description)
    event.threat_level = request.form.get('threat_level', event.threat_level)
    event.analysis_status = request.form.get('analysis_status', event.analysis_status)
    event.org = request.form.get('org', event.org)
    event.is_published = request.form.get('is_published') == 'on'

    event_date = request.form.get('event_date')
    if event_date:
        event.event_date = datetime.strptime(event_date, '%Y-%m-%d').date()

    db.session.commit()

    if event.misp_event_id:
        try:
            misp = _misp_client()
            misp.update_event(event.misp_event_id, info=event.title)
        except Exception as exc:  # noqa: BLE001
            flash(f'Local update saved, but MISP sync failed: {exc}', 'warning')

    ActivityLog.log(current_user.id, 'UPDATE_EVENT', f'Updated event: {event.title}',
                     request.remote_addr)
    flash('Event updated.', 'success')
    return redirect(url_for('event.view_event', event_id=event.id))


@event_bp.route('/events/<int:event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    event = ThreatEvent.query.get_or_404(event_id)
    title = event.title
    db.session.delete(event)
    db.session.commit()
    ActivityLog.log(current_user.id, 'DELETE_EVENT', f'Deleted event: {title}', request.remote_addr)
    flash('Event deleted.', 'info')
    return redirect(url_for('event.list_events'))


# ---------------------------------------------------------------------------
# REST API (JSON)
# ---------------------------------------------------------------------------
@event_bp.route('/api/events', methods=['GET'])
@login_required
def api_list_events():
    events = ThreatEvent.query.order_by(ThreatEvent.created_at.desc()).limit(200).all()
    return jsonify([e.to_dict() for e in events])


@event_bp.route('/api/events/<int:event_id>', methods=['GET'])
@login_required
def api_get_event(event_id):
    event = ThreatEvent.query.get_or_404(event_id)
    data = event.to_dict()
    data['iocs'] = [i.to_dict() for i in event.iocs.all()]
    return jsonify(data)


@event_bp.route('/api/events', methods=['POST'])
@login_required
def api_create_event():
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400

    event = ThreatEvent(
        title=title,
        description=data.get('description', ''),
        threat_level=data.get('threat_level') or 'medium',
        analysis_status=data.get('analysis_status') or 'initial',
        org=data.get('org'),
        event_date=datetime.strptime(data['event_date'], '%Y-%m-%d').date()
        if data.get('event_date') else datetime.utcnow().date(),
        created_by=current_user.id
    )
    db.session.add(event)
    db.session.commit()
    ActivityLog.log(current_user.id, 'API_CREATE_EVENT', f'Created event via API: {title}',
                     request.remote_addr)
    return jsonify(event.to_dict()), 201
