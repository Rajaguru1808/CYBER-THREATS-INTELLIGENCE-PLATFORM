"""
Threat severity classification.

Combines signals from VirusTotal (malicious/suspicious vote counts),
AlienVault OTX (pulse count), and AbuseIPDB (abuse confidence score) into
a single 0-100 confidence score and a low/medium/high/critical severity
label. The weighting is intentionally simple/transparent for a mini-project,
but isolated here so it can be refined without touching route code.
"""

SEVERITY_THRESHOLDS = (
    (85, 'critical'),
    (60, 'high'),
    (30, 'medium'),
    (0, 'low'),
)


def score_to_severity(score):
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return 'low'


def compute_severity(vt_stats=None, otx_pulse_count=0, abuse_score=0):
    """
    vt_stats: dict with 'malicious' and 'suspicious' counts (from VirusTotalService.extract_reputation)
    otx_pulse_count: int, number of OTX pulses referencing the indicator
    abuse_score: int 0-100 AbuseIPDB confidence score

    Returns: (confidence_score: int 0-100, severity_label: str)
    """
    vt_stats = vt_stats or {}
    malicious = vt_stats.get('malicious', 0)
    suspicious = vt_stats.get('suspicious', 0)

    # VT: each malicious vendor verdict weighted heavily, suspicious less so.
    vt_component = min(malicious * 8 + suspicious * 3, 60)

    # OTX: presence in threat pulses is a strong signal, capped contribution.
    otx_component = min(otx_pulse_count * 4, 25)

    # AbuseIPDB: already 0-100, scale down to contribute up to 15 points.
    abuse_component = min(abuse_score * 0.15, 15)

    total_score = round(vt_component + otx_component + abuse_component)
    total_score = max(0, min(total_score, 100))

    return total_score, score_to_severity(total_score)


def classify_event_threat_level(ioc_list):
    """
    Given a list of IOCAttribute-like dicts with a 'severity' key, derive an
    overall event threat_level as the highest severity among its IOCs.
    """
    order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    if not ioc_list:
        return 'medium'
    highest = max(ioc_list, key=lambda i: order.get(i.get('severity', 'low'), 0))
    return highest.get('severity', 'medium')
