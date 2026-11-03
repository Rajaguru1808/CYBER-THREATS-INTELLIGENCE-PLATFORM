"""
PDF report generation using ReportLab.

Generates professional-looking PDF reports for:
  - A single threat event (with its IOCs)
  - A single IOC
  - A platform-wide summary report (stats + recent events)

Files are written to app.config['REPORTS_FOLDER'] and referenced from the
`reports` DB table.
"""
import os
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

SEVERITY_COLORS = {
    'critical': colors.HexColor('#dc3545'),
    'high': colors.HexColor('#fd7e14'),
    'medium': colors.HexColor('#ffc107'),
    'low': colors.HexColor('#28a745'),
}


def _base_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CTITitle', fontSize=20, leading=24,
                               textColor=colors.HexColor('#0d1b2a'), spaceAfter=12))
    styles.add(ParagraphStyle(name='CTISubtitle', fontSize=11, leading=14,
                               textColor=colors.HexColor('#6c757d'), spaceAfter=20))
    styles.add(ParagraphStyle(name='SectionHeader', fontSize=14, leading=18,
                               textColor=colors.HexColor('#1b263b'), spaceBefore=16, spaceAfter=8))
    # Used for long table-cell content (e.g. IOC values/URLs) so ReportLab
    # wraps the text onto multiple lines inside the cell instead of letting
    # a single unbroken string overflow into the next column.
    styles.add(ParagraphStyle(name='CellWrap', fontSize=8, leading=10,
                               wordWrap='CJK'))
    styles.add(ParagraphStyle(name='CellWrapWhite', parent=styles['CellWrap'],
                               textColor=colors.white))
    return styles


def _cell(text, style):
    """Build a table-cell Paragraph from raw, untrusted text (IOC values,
    event titles, etc. can contain '&', '<', '>' - e.g. a URL query string
    like '?a=1&b=2'). Paragraph treats its text as mini-XML, so unescaped
    text is silently mangled or dropped (e.g. '<Demo>' disappears,
    '&b=2' becomes '&b;=2'). Escaping first keeps the original text intact."""
    return Paragraph(xml_escape('' if text is None else str(text)), style)


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(2 * cm, 1 * cm, 'CTI Platform - Confidential Threat Intelligence Report')
    canvas.drawRightString(A4[0] - 2 * cm, 1 * cm, f'Page {doc.page}')
    canvas.restoreState()


def generate_event_report(event, iocs, output_path):
    """Build a PDF report for a single threat event and its IOCs."""
    styles = _base_styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             leftMargin=2 * cm, rightMargin=2 * cm,
                             topMargin=2 * cm, bottomMargin=2 * cm)
    story = []

    story.append(Paragraph('Threat Event Report', styles['CTITitle']))
    story.append(Paragraph(
        f'Generated on {datetime.utcnow().strftime("%d %b %Y %H:%M UTC")}',
        styles['CTISubtitle']
    ))

    story.append(_cell(event.title, styles['SectionHeader']))
    meta_table = Table([
        ['Threat Level', event.threat_level.upper()],
        ['Analysis Status', event.analysis_status.title()],
        ['Organization', event.org or 'N/A'],
        ['Event Date', str(event.event_date) if event.event_date else 'N/A'],
        ['MISP Event ID', event.misp_event_id or 'Not linked to MISP'],
        ['Total IOCs', str(len(iocs))],
    ], colWidths=[5 * cm, 10 * cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#eef2f7')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    if event.description:
        story.append(Paragraph('Description', styles['SectionHeader']))
        story.append(_cell(event.description, styles['BodyText']))

    story.append(Paragraph('Indicators of Compromise', styles['SectionHeader']))
    if iocs:
        header = ['Type', 'Value', 'Severity', 'Source', 'Correlated']
        table_data = [[_cell(h, styles['CellWrapWhite']) for h in header]]
        for ioc in iocs:
            severity_color = SEVERITY_COLORS.get(ioc.severity, colors.black)
            severity_style = ParagraphStyle(
                name=f'Sev_{ioc.severity}', parent=styles['CellWrap'], textColor=severity_color
            )
            table_data.append([
                _cell(ioc.ioc_type.replace('_', ' ').upper(), styles['CellWrap']),
                # Full value, wrapped onto multiple lines inside the cell
                # (wordWrap='CJK' lets it break even inside an unbroken
                # URL/hash) instead of being truncated or overflowing.
                # xml_escape (inside _cell) keeps '&'/'<'/'>' in the raw
                # IOC value (common in URL query strings) from being
                # mangled or silently dropped by Paragraph's XML parser.
                _cell(ioc.ioc_value, styles['CellWrap']),
                _cell(ioc.severity.upper(), severity_style),
                _cell(ioc.source, styles['CellWrap']),
                _cell('Yes' if ioc.is_correlated else 'No', styles['CellWrap']),
            ])
        ioc_table = Table(table_data, colWidths=[2.3 * cm, 7.2 * cm, 2.2 * cm, 2.2 * cm, 2.1 * cm], repeatRows=1)
        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1b263b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]
        ioc_table.setStyle(TableStyle(style_cmds))
        story.append(ioc_table)
    else:
        story.append(Paragraph('No IOCs recorded for this event.', styles['BodyText']))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path


def generate_summary_report(stats, recent_events, output_path):
    """Build a platform-wide summary PDF report."""
    styles = _base_styles()
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             leftMargin=2 * cm, rightMargin=2 * cm,
                             topMargin=2 * cm, bottomMargin=2 * cm)
    story = [
        Paragraph('CTI Platform Summary Report', styles['CTITitle']),
        Paragraph(f'Generated on {datetime.utcnow().strftime("%d %b %Y %H:%M UTC")}', styles['CTISubtitle']),
        Paragraph('Key Statistics', styles['SectionHeader']),
    ]

    stats_table = Table([
        ['Total Threat Events', str(stats.get('total_events', 0))],
        ['Critical Threats', str(stats.get('critical_events', 0))],
        ['Total IOCs', str(stats.get('total_iocs', 0))],
        ['Correlated IOCs', str(stats.get('correlated_iocs', 0))],
    ], colWidths=[7 * cm, 8 * cm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#eef2f7')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph('Recent Threat Events', styles['SectionHeader']))
    if recent_events:
        header = ['Title', 'Threat Level', 'Status', 'Date']
        table_data = [[_cell(h, styles['CellWrapWhite']) for h in header]]
        for e in recent_events:
            table_data.append([
                _cell(e.title, styles['CellWrap']),
                _cell(e.threat_level.upper(), styles['CellWrap']),
                _cell(e.analysis_status.title(), styles['CellWrap']),
                _cell(str(e.event_date) if e.event_date else 'N/A', styles['CellWrap']),
            ])
        event_table = Table(table_data, colWidths=[7 * cm, 3 * cm, 3 * cm, 2 * cm], repeatRows=1)
        event_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1b263b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(event_table)
    else:
        story.append(Paragraph('No recent events.', styles['BodyText']))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path


def build_report_filename(prefix):
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    safe_prefix = ''.join(c for c in prefix if c.isalnum() or c in ('_', '-'))[:40]
    return f'{safe_prefix}_{ts}.pdf'
