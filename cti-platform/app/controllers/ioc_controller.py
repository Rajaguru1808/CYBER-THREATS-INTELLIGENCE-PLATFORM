"""IOC (Indicator of Compromise) management: CRUD, search, and enrichment
via VirusTotal / OTX / AbuseIPDB."""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user

from app.extensions import db
from app.models.ioc import IOCAttribute
from app.models.event import ThreatEvent
from app.models.activity_log import ActivityLog
from app.utils.validators import validate_ioc, detect_ioc_type
from app.services.virustotal_service import VirusTotalService
from app.services.otx_service import OTXService
from app.services.abuseipdb_service import AbuseIPDBService
from app.services.severity_service import compute_severity
from app.services.correlation_service import update_correlation_flags
from app.models.api_config import APIConfiguration

ioc_bp = Blueprint('ioc', __name__)


def _configured_key(service_name):
    """Read the API key saved on Settings > API Configuration (DB).
    Falls back to None (services will then fall back to the environment
    variable / .env) so behaviour degrades gracefully if the admin hasn't
    filled in the Settings page yet."""
    cfg = APIConfiguration.query.filter_by(service_name=service_name).first()
    return cfg.api_key if cfg and cfg.api_key else None


@ioc_bp.route('/iocs')
@login_required
def list_iocs():
    page = request.args.get('page', 1, type=int)
    ioc_type = request.args.get('type', '')
    severity = request.args.get('severity', '')
    query_text = request.args.get('q', '').strip()
    correlated = request.args.get('correlated', '')

    query = IOCAttribute.query
    if ioc_type:
        query = query.filter_by(ioc_type=ioc_type)
    if severity:
        query = query.filter_by(severity=severity)
    if query_text:
        query = query.filter(IOCAttribute.ioc_value.ilike(f'%{query_text}%'))
    if correlated == 'yes':
        query = query.filter_by(is_correlated=True)

    pagination = query.order_by(IOCAttribute.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )
    events = ThreatEvent.query.order_by(ThreatEvent.title).all()
    return render_template('ioc_management.html', pagination=pagination,
                            iocs=pagination.items, events=events,
                            filters={'type': ioc_type, 'severity': severity, 'q': query_text,
                                     'correlated': correlated})


@ioc_bp.route('/iocs/bulk-check', methods=['GET'])
@login_required
def bulk_check_form():
    events = ThreatEvent.query.order_by(ThreatEvent.title).all()
    return render_template('bulk_check.html', events=events)


@ioc_bp.route('/iocs/bulk-check', methods=['POST'])
@login_required
def bulk_check():
    """Paste a list of IPs / domains / URLs / hashes / emails (one per line)
    and automatically type-detect, save, and threat-check every one of them
    against VirusTotal / OTX / AbuseIPDB in a single go."""
    raw_values = request.form.get('values', '')
    event_id = request.form.get('event_id') or None

    lines = [line.strip() for line in raw_values.splitlines()]
    lines = [line for line in lines if line]

    results = []  # (value, type, severity, status) for the summary table
    added, skipped, failed = 0, 0, 0

    for value in lines:
        ioc_type = detect_ioc_type(value)
        if not ioc_type:
            results.append({'value': value, 'type': None, 'severity': None, 'status': 'Unrecognised format'})
            skipped += 1
            continue

        # Skip values already in the database instead of creating duplicates.
        existing = IOCAttribute.query.filter_by(ioc_type=ioc_type, ioc_value=value).first()
        if existing:
            results.append({'value': value, 'type': ioc_type, 'severity': existing.severity,
                             'status': 'Already exists'})
            skipped += 1
            continue

        is_valid, error = validate_ioc(ioc_type, value)
        if not is_valid:
            results.append({'value': value, 'type': ioc_type, 'severity': None, 'status': error})
            failed += 1
            continue

        ioc = IOCAttribute(
            event_id=event_id, ioc_type=ioc_type, ioc_value=value,
            category='Network activity', severity='medium', source='bulk',
            created_by=current_user.id
        )
        db.session.add(ioc)
        db.session.commit()
        update_correlation_flags(ioc)

        score, severity = _run_enrichment(ioc)
        results.append({'value': value, 'type': ioc_type,
                         'severity': severity or ioc.severity, 'status': 'Added & checked'})
        added += 1

    if added:
        ActivityLog.log(current_user.id, 'BULK_ADD_IOC',
                         f'Bulk-added {added} IOCs ({skipped} skipped, {failed} failed)',
                         request.remote_addr)

    events = ThreatEvent.query.order_by(ThreatEvent.title).all()
    flash(f'{added} added & checked, {skipped} skipped, {failed} failed.',
          'success' if added else 'warning')
    return render_template('bulk_check.html', events=events, results=results)


@ioc_bp.route('/iocs/create', methods=['POST'])
@login_required
def create_ioc():
    ioc_type = request.form.get('ioc_type')
    ioc_value = request.form.get('ioc_value', '').strip()
    event_id = request.form.get('event_id') or None
    category = request.form.get('category', 'Network activity')
    severity = request.form.get('severity', 'medium')
    tags = request.form.get('tags', '').strip()

    is_valid, error = validate_ioc(ioc_type, ioc_value)
    if not is_valid:
        flash(error, 'danger')
        return redirect(url_for('ioc.list_iocs'))

    ioc = IOCAttribute(
        event_id=event_id, ioc_type=ioc_type, ioc_value=ioc_value,
        category=category, severity=severity, tags=tags,
        source='manual', created_by=current_user.id
    )
    db.session.add(ioc)
    db.session.commit()

    update_correlation_flags(ioc)
    ActivityLog.log(current_user.id, 'CREATE_IOC', f'Added IOC: {ioc_value}', request.remote_addr)

    # Automatically check the new IOC against VirusTotal / OTX / AbuseIPDB
    # right away, so the user doesn't have to click "refresh" separately.
    score, severity = _run_enrichment(ioc)
    if severity is not None:
        ActivityLog.log(current_user.id, 'ENRICH_IOC',
                         f'Auto-enriched IOC {ioc.ioc_value}: score={score} severity={severity}',
                         request.remote_addr)
        flash(f'IOC added. Threat check complete — severity: {severity.upper()} '
              f'(confidence {score}/100).', 'success')
    else:
        flash('IOC added successfully.', 'success')

    return redirect(url_for('ioc.list_iocs'))


@ioc_bp.route('/iocs/<int:ioc_id>/update', methods=['POST'])
@login_required
def update_ioc(ioc_id):
    ioc = IOCAttribute.query.get_or_404(ioc_id)
    ioc.severity = request.form.get('severity', ioc.severity)
    ioc.category = request.form.get('category', ioc.category)
    ioc.tags = request.form.get('tags', ioc.tags)
    event_id = request.form.get('event_id')
    ioc.event_id = event_id or None
    db.session.commit()

    update_correlation_flags(ioc)
    ActivityLog.log(current_user.id, 'UPDATE_IOC', f'Updated IOC: {ioc.ioc_value}', request.remote_addr)
    flash('IOC updated.', 'success')
    return redirect(url_for('ioc.list_iocs'))


@ioc_bp.route('/iocs/<int:ioc_id>/delete', methods=['POST'])
@login_required
def delete_ioc(ioc_id):
    ioc = IOCAttribute.query.get_or_404(ioc_id)
    value = ioc.ioc_value
    db.session.delete(ioc)
    db.session.commit()
    ActivityLog.log(current_user.id, 'DELETE_IOC', f'Deleted IOC: {value}', request.remote_addr)
    flash('IOC deleted.', 'info')
    return redirect(url_for('ioc.list_iocs'))


@ioc_bp.route('/search', methods=['GET'])
@login_required
def search():
    query_text = request.args.get('q', '').strip()
    results = None
    detected_type = None
    if query_text:
        detected_type = detect_ioc_type(query_text)
        results = IOCAttribute.query.filter(
            IOCAttribute.ioc_value.ilike(f'%{query_text}%')
        ).order_by(IOCAttribute.created_at.desc()).all()
    return render_template('search.html', query_text=query_text, results=results,
                            detected_type=detected_type)


def _run_enrichment(ioc):
    """Shared enrichment logic: look up an IOC against VirusTotal / OTX /
    AbuseIPDB and recompute its severity + confidence score.
    Used both by the manual 'refresh' button and by automatic enrichment
    right after an IOC is created."""
    vt_stats = {}
    otx_pulses = 0
    abuse_score = 0
    notes = []

    if ioc.ioc_type == 'ip':
        vt = VirusTotalService(api_key=_configured_key('virustotal'))
        vt_result = vt.lookup_ip(ioc.ioc_value)
        vt_stats = VirusTotalService.extract_reputation(vt_result)

        otx = OTXService(api_key=_configured_key('otx'))
        otx_result = otx.lookup_ip(ioc.ioc_value)
        otx_pulses = OTXService.extract_pulse_count(otx_result)

        abuse = AbuseIPDBService(api_key=_configured_key('abuseipdb'))
        abuse_result = abuse.check_ip(ioc.ioc_value)
        abuse_score = AbuseIPDBService.extract_score(abuse_result)
        if abuse_score == -1:
            abuse_score = 0
            notes.append('AbuseIPDB unavailable')

    elif ioc.ioc_type == 'domain':
        vt = VirusTotalService(api_key=_configured_key('virustotal'))
        vt_stats = VirusTotalService.extract_reputation(vt.lookup_domain(ioc.ioc_value))
        otx = OTXService(api_key=_configured_key('otx'))
        otx_pulses = OTXService.extract_pulse_count(otx.lookup_domain(ioc.ioc_value))

    elif ioc.ioc_type == 'url':
        vt = VirusTotalService(api_key=_configured_key('virustotal'))
        vt_stats = VirusTotalService.extract_reputation(vt.lookup_url(ioc.ioc_value))
        otx = OTXService(api_key=_configured_key('otx'))
        otx_pulses = OTXService.extract_pulse_count(otx.lookup_url(ioc.ioc_value))

    elif ioc.ioc_type.startswith('hash'):
        vt = VirusTotalService(api_key=_configured_key('virustotal'))
        vt_stats = VirusTotalService.extract_reputation(vt.lookup_hash(ioc.ioc_value))
        otx = OTXService(api_key=_configured_key('otx'))
        otx_pulses = OTXService.extract_pulse_count(otx.lookup_hash(ioc.ioc_value))

    elif ioc.ioc_type == 'email':
        # VirusTotal / OTX don't have a "check this email address" lookup.
        # The closest useful signal is the sending domain's reputation,
        # so we extract it and check that instead.
        domain_part = ioc.ioc_value.split('@')[-1].strip().lower()
        vt = VirusTotalService(api_key=_configured_key('virustotal'))
        vt_stats = VirusTotalService.extract_reputation(vt.lookup_domain(domain_part))
        otx = OTXService(api_key=_configured_key('otx'))
        otx_pulses = OTXService.extract_pulse_count(otx.lookup_domain(domain_part))
        notes.append(f'Checked via sending domain: {domain_part}')

    else:
        return None, None

    score, severity = compute_severity(vt_stats, otx_pulses, abuse_score)
    ioc.severity = severity
    ioc.confidence_score = score
    db.session.commit()
    return score, severity


@ioc_bp.route('/iocs/<int:ioc_id>/enrich', methods=['POST'])
@login_required
def enrich_ioc(ioc_id):
    """Manual 'refresh' button: look up an IOC against VirusTotal / OTX /
    AbuseIPDB and recompute severity."""
    ioc = IOCAttribute.query.get_or_404(ioc_id)
    score, severity = _run_enrichment(ioc)

    if severity is None:
        flash('Enrichment is not supported for this IOC type.', 'warning')
        return redirect(url_for('ioc.list_iocs'))

    ActivityLog.log(current_user.id, 'ENRICH_IOC',
                     f'Enriched IOC {ioc.ioc_value}: score={score} severity={severity}',
                     request.remote_addr)
    flash(f'Enrichment complete. New severity: {severity.upper()} (confidence {score}/100).', 'success')
    return redirect(url_for('ioc.list_iocs'))


# ---------------------------------------------------------------------------
# REST API (JSON) endpoints for IOCs — used by external tools / automation
# ---------------------------------------------------------------------------
@ioc_bp.route('/api/iocs', methods=['GET'])
@login_required
def api_list_iocs():
    iocs = IOCAttribute.query.order_by(IOCAttribute.created_at.desc()).limit(200).all()
    return jsonify([i.to_dict() for i in iocs])


@ioc_bp.route('/api/iocs', methods=['POST'])
@login_required
def api_create_ioc():
    data = request.get_json(force=True, silent=True) or {}
    ioc_type = data.get('ioc_type')
    ioc_value = (data.get('ioc_value') or '').strip()

    is_valid, error = validate_ioc(ioc_type, ioc_value)
    if not is_valid:
        return jsonify({'error': error}), 400

    ioc = IOCAttribute(
        ioc_type=ioc_type, ioc_value=ioc_value,
        category=data.get('category') or 'Network activity',
        severity=data.get('severity') or 'medium',
        tags=data.get('tags') or '',
        event_id=data.get('event_id'),
        source=data.get('source') or 'api',
        created_by=current_user.id
    )
    db.session.add(ioc)
    db.session.commit()
    update_correlation_flags(ioc)
    # Same automatic threat check as the web UI's "Add IOC" form.
    _run_enrichment(ioc)
    ActivityLog.log(current_user.id, 'API_CREATE_IOC', f'Created IOC via API: {ioc_value}',
                     request.remote_addr)
    return jsonify(ioc.to_dict()), 201


@ioc_bp.route('/api/iocs/<int:ioc_id>', methods=['DELETE'])
@login_required
def api_delete_ioc(ioc_id):
    ioc = IOCAttribute.query.get_or_404(ioc_id)
    db.session.delete(ioc)
    db.session.commit()
    return jsonify({'message': 'IOC deleted'}), 200


@ioc_bp.route('/api/search', methods=['GET'])
@login_required
def api_search():
    query_text = request.args.get('q', '').strip()
    if not query_text:
        return jsonify({'error': 'Missing query parameter "q"'}), 400
    results = IOCAttribute.query.filter(
        IOCAttribute.ioc_value.ilike(f'%{query_text}%')
    ).limit(100).all()
    return jsonify({
        'query': query_text,
        'detected_type': detect_ioc_type(query_text),
        'results': [r.to_dict() for r in results]
    })
