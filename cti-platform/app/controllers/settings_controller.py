"""Settings: API configuration (MISP/VT/OTX/AbuseIPDB) and activity log viewer."""
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user

from app.extensions import db
from app.models.api_config import APIConfiguration
from app.models.activity_log import ActivityLog
from app.utils.decorators import admin_required
from app.services.misp_service import MISPService
from app.services.virustotal_service import VirusTotalService
from app.services.otx_service import OTXService
from app.services.abuseipdb_service import AbuseIPDBService

settings_bp = Blueprint('settings', __name__)


@settings_bp.route('/settings')
@login_required
@admin_required
def index():
    configs = {c.service_name: c for c in APIConfiguration.query.all()}
    return render_template('settings.html', configs=configs, active_tab='api')


@settings_bp.route('/settings/api/<service_name>', methods=['POST'])
@login_required
@admin_required
def update_api_config(service_name):
    valid_services = {'misp', 'virustotal', 'otx', 'abuseipdb'}
    if service_name not in valid_services:
        flash('Unknown service.', 'danger')
        return redirect(url_for('settings.index'))

    config = APIConfiguration.query.filter_by(service_name=service_name).first()
    if config is None:
        config = APIConfiguration(service_name=service_name)
        db.session.add(config)

    config.base_url = request.form.get('base_url', '').strip()
    new_key = request.form.get('api_key', '').strip()
    if new_key:  # keep existing key if left blank
        config.api_key = new_key
    config.is_active = request.form.get('is_active') == 'on'
    db.session.commit()

    ActivityLog.log(current_user.id, 'UPDATE_API_CONFIG', f'Updated {service_name} configuration',
                     request.remote_addr)
    flash(f'{service_name.upper()} configuration saved.', 'success')
    return redirect(url_for('settings.index'))


@settings_bp.route('/settings/api/<service_name>/test', methods=['POST'])
@login_required
@admin_required
def test_api_config(service_name):
    config = APIConfiguration.query.filter_by(service_name=service_name).first()
    if config is None:
        return jsonify({'success': False, 'message': 'Not configured'}), 400

    success, message = False, 'Unknown service'
    try:
        if service_name == 'misp':
            svc = MISPService(url=config.base_url, api_key=config.api_key)
            success, message = svc.test_connection()
        elif service_name == 'virustotal':
            svc = VirusTotalService(api_key=config.api_key)
            result = svc.lookup_ip('8.8.8.8')
            success = 'error' not in result
            message = 'Connected' if success else result.get('error')
        elif service_name == 'otx':
            svc = OTXService(api_key=config.api_key)
            result = svc.lookup_ip('8.8.8.8')
            success = 'error' not in result
            message = 'Connected' if success else result.get('error')
        elif service_name == 'abuseipdb':
            svc = AbuseIPDBService(api_key=config.api_key)
            result = svc.check_ip('8.8.8.8')
            success = 'error' not in result
            message = 'Connected' if success else result.get('error')
    except Exception as exc:  # noqa: BLE001
        success, message = False, str(exc)

    config.status = 'connected' if success else 'disconnected'
    config.last_checked = datetime.utcnow()
    db.session.commit()

    return jsonify({'success': success, 'message': message, 'status': config.status})


@settings_bp.route('/settings/activity-logs')
@login_required
@admin_required
def activity_logs():
    page = request.args.get('page', 1, type=int)
    pagination = ActivityLog.query.order_by(ActivityLog.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    return render_template('activity_logs.html', pagination=pagination, logs=pagination.items)


@settings_bp.route('/settings/activity-logs/clear', methods=['POST'])
@login_required
@admin_required
def clear_activity_logs():
    deleted = ActivityLog.query.delete()
    db.session.commit()
    # Log the clear action itself, so there's a record that it happened.
    ActivityLog.log(current_user.id, 'CLEAR_ACTIVITY_LOGS', f'Cleared {deleted} activity log entries',
                     request.remote_addr)
    flash('Activity history cleared.', 'success')
    return redirect(url_for('settings.activity_logs'))
