"""Import threat intelligence: pull recent MISP events/attributes or OTX pulses
into the local database as ThreatEvents + IOCAttributes."""
from datetime import datetime
from flask import Blueprint, redirect, url_for, flash, request
from flask_login import login_required, current_user

from app.extensions import db
from app.models.event import ThreatEvent
from app.models.ioc import IOCAttribute
from app.models.activity_log import ActivityLog
from app.services.misp_service import MISPService, PYMISP_AVAILABLE
from app.services.otx_service import OTXService
from app.services.correlation_service import recompute_all_correlations
from app.models.api_config import APIConfiguration
from app.controllers.ioc_controller import _run_enrichment

import_bp = Blueprint('import_data', __name__)

MISP_TYPE_MAP = {
    'ip-dst': 'ip', 'ip-src': 'ip', 'domain': 'domain', 'url': 'url',
    'email-src': 'email', 'email-dst': 'email',
    'md5': 'hash_md5', 'sha1': 'hash_sha1', 'sha256': 'hash_sha256',
}


@import_bp.route('/import/misp', methods=['POST'])
@login_required
def import_from_misp():
    if not PYMISP_AVAILABLE:
        flash('pymisp is not installed on the server. Run: pip install pymisp', 'danger')
        return redirect(url_for('event.list_events'))

    try:
        misp_config = APIConfiguration.query.filter_by(service_name='misp').first()
        misp = MISPService(
            url=misp_config.base_url if misp_config and misp_config.base_url else None,
            api_key=misp_config.api_key if misp_config and misp_config.api_key else None,
        )
        misp_events = misp.get_events(limit=25)
    except Exception as exc:  # noqa: BLE001
        flash(f'MISP import failed: {exc}', 'danger')
        return redirect(url_for('event.list_events'))

    imported_events, imported_iocs = 0, 0
    for me in misp_events:
        existing = ThreatEvent.query.filter_by(misp_uuid=str(me.uuid)).first()
        if existing:
            continue

        level_map = {'1': 'critical', '2': 'medium', '3': 'low', '4': 'medium'}
        misp_date = getattr(me, 'date', None)
        event = ThreatEvent(
            misp_event_id=str(me.id), misp_uuid=str(me.uuid), title=me.info,
            threat_level=level_map.get(str(getattr(me, 'threat_level_id', '2')), 'medium'),
            analysis_status='ongoing', org=getattr(me, 'org', None),
            is_published=bool(getattr(me, 'published', False)),
            # Use the MISP event's own date if it has one, else default to today
            # so "Event Date" is never left blank ("N/A") after import.
            event_date=misp_date if misp_date else datetime.utcnow().date(),
            created_by=current_user.id
        )
        db.session.add(event)
        db.session.flush()  # get event.id before committing
        imported_events += 1

        for attr in getattr(me, 'attributes', []):
            mapped_type = MISP_TYPE_MAP.get(attr.type)
            if not mapped_type:
                continue
            ioc = IOCAttribute(
                event_id=event.id, ioc_type=mapped_type, ioc_value=attr.value,
                category=getattr(attr, 'category', 'Network activity'),
                severity='medium', source='misp', created_by=current_user.id
            )
            db.session.add(ioc)
            db.session.flush()
            # Real automatic threat check for every imported IOC (VT/OTX/AbuseIPDB),
            # not just a placeholder severity.
            _run_enrichment(ioc)
            imported_iocs += 1

    db.session.commit()
    recompute_all_correlations()

    ActivityLog.log(current_user.id, 'IMPORT_MISP',
                     f'Imported {imported_events} events / {imported_iocs} IOCs from MISP',
                     request.remote_addr)
    flash(f'Imported {imported_events} events and {imported_iocs} IOCs from MISP.', 'success')
    return redirect(url_for('event.list_events'))


@import_bp.route('/import/otx', methods=['POST'])
@login_required
def import_from_otx():
    # Use the API key saved in Settings > API Configuration (DB), not the
    # server environment variable, so "Import from OTX" matches what the
    # user configured and tested on the Settings page.
    otx_config = APIConfiguration.query.filter_by(service_name='otx').first()
    api_key = otx_config.api_key if otx_config and otx_config.api_key else None
    otx = OTXService(api_key=api_key)
    pulses = otx.get_subscribed_pulses(limit=10)

    if isinstance(pulses, dict) and 'error' in pulses:
        flash(f'OTX import failed: {pulses["error"]}', 'danger')
        return redirect(url_for('event.list_events'))

    imported_events, imported_iocs = 0, 0
    for pulse in pulses.get('results', []):
        title = pulse.get('name', 'OTX Pulse')
        existing = ThreatEvent.query.filter_by(title=title, org='AlienVault OTX').first()
        if existing:
            continue

        # OTX pulses include a 'created' timestamp (ISO format); use its date
        # if present, else default to today so this is never left blank.
        pulse_date = None
        pulse_created = pulse.get('created')
        if pulse_created:
            try:
                pulse_date = datetime.strptime(pulse_created[:10], '%Y-%m-%d').date()
            except (ValueError, TypeError):
                pulse_date = None

        event = ThreatEvent(
            title=title, description=pulse.get('description', ''),
            threat_level='high', analysis_status='ongoing', org='AlienVault OTX',
            event_date=pulse_date or datetime.utcnow().date(),
            created_by=current_user.id
        )
        db.session.add(event)
        db.session.flush()
        imported_events += 1

        for indicator in pulse.get('indicators', []):
            otx_type_map = {
                'IPv4': 'ip', 'IPv6': 'ip', 'domain': 'domain', 'hostname': 'domain',
                'URL': 'url', 'email': 'email', 'FileHash-MD5': 'hash_md5',
                'FileHash-SHA1': 'hash_sha1', 'FileHash-SHA256': 'hash_sha256',
            }
            mapped_type = otx_type_map.get(indicator.get('type'))
            if not mapped_type:
                continue
            ioc = IOCAttribute(
                event_id=event.id, ioc_type=mapped_type, ioc_value=indicator.get('indicator', ''),
                category='External analysis', severity='medium', source='otx',
                created_by=current_user.id
            )
            db.session.add(ioc)
            db.session.flush()
            # Real automatic threat check for every imported IOC (VT/OTX/AbuseIPDB),
            # not just a placeholder severity.
            _run_enrichment(ioc)
            imported_iocs += 1

    db.session.commit()
    recompute_all_correlations()

    ActivityLog.log(current_user.id, 'IMPORT_OTX',
                     f'Imported {imported_events} events / {imported_iocs} IOCs from OTX',
                     request.remote_addr)
    flash(f'Imported {imported_events} events and {imported_iocs} IOCs from AlienVault OTX.', 'success')
    return redirect(url_for('event.list_events'))
