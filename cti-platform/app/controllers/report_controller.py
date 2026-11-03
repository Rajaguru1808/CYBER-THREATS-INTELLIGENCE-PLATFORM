"""Report generation: PDF reports for events, IOC sets, or platform summary."""
import os

from flask import Blueprint, render_template, request, redirect, url_for, flash, \
    send_from_directory, current_app
from flask_login import login_required, current_user

from app.extensions import db
from app.models.report import Report
from app.models.event import ThreatEvent
from app.models.activity_log import ActivityLog
from app.services.pdf_service import generate_event_report, generate_summary_report, \
    build_report_filename
from app.controllers.dashboard_controller import _gather_stats

report_bp = Blueprint('report', __name__)


@report_bp.route('/reports')
@login_required
def list_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    events = ThreatEvent.query.order_by(ThreatEvent.title).all()
    return render_template('reports.html', reports=reports, events=events)


@report_bp.route('/reports/generate/event/<int:event_id>', methods=['POST'])
@login_required
def generate_for_event(event_id):
    event = ThreatEvent.query.get_or_404(event_id)
    iocs = event.iocs.all()

    filename = build_report_filename(f'event_{event.id}')
    output_path = os.path.join(current_app.config['REPORTS_FOLDER'], filename)
    generate_event_report(event, iocs, output_path)

    report = Report(
        title=f'Event Report: {event.title}', report_type='event',
        event_id=event.id, file_path=filename, generated_by=current_user.id
    )
    db.session.add(report)
    db.session.commit()

    ActivityLog.log(current_user.id, 'GENERATE_REPORT', f'Generated report for event: {event.title}',
                     request.remote_addr)
    flash('PDF report generated successfully.', 'success')
    return redirect(url_for('report.list_reports'))


@report_bp.route('/reports/generate/summary', methods=['POST'])
@login_required
def generate_summary():
    stats = _gather_stats()
    recent_events = stats['recent_events']

    filename = build_report_filename('platform_summary')
    output_path = os.path.join(current_app.config['REPORTS_FOLDER'], filename)
    generate_summary_report(stats, recent_events, output_path)

    report = Report(
        title='Platform Summary Report', report_type='summary',
        file_path=filename, generated_by=current_user.id
    )
    db.session.add(report)
    db.session.commit()

    ActivityLog.log(current_user.id, 'GENERATE_REPORT', 'Generated platform summary report',
                     request.remote_addr)
    flash('Summary report generated successfully.', 'success')
    return redirect(url_for('report.list_reports'))


@report_bp.route('/reports/<int:report_id>/download')
@login_required
def download_report(report_id):
    report = Report.query.get_or_404(report_id)
    return send_from_directory(current_app.config['REPORTS_FOLDER'], report.file_path,
                                as_attachment=True)


@report_bp.route('/reports/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)
    file_path = os.path.join(current_app.config['REPORTS_FOLDER'], report.file_path)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(report)
    db.session.commit()
    flash('Report deleted.', 'info')
    return redirect(url_for('report.list_reports'))
