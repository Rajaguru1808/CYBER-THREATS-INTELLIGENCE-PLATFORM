"""
AbuseIPDB API integration (used for IP reputation lookups).
Docs: https://docs.abuseipdb.com/
"""
import requests
from flask import current_app

BASE_URL = 'https://api.abuseipdb.com/api/v2'
TIMEOUT = 15


class AbuseIPDBService:
    def __init__(self, api_key=None):
        self.api_key = api_key or current_app.config.get('ABUSEIPDB_API_KEY')

    def _headers(self):
        return {'Key': self.api_key, 'Accept': 'application/json'}

    def check_ip(self, ip, max_age_days=90):
        if not self.api_key:
            return {'error': 'AbuseIPDB API key is not configured.'}
        try:
            resp = requests.get(
                f'{BASE_URL}/check',
                headers=self._headers(),
                params={'ipAddress': ip, 'maxAgeInDays': max_age_days, 'verbose': True},
                timeout=TIMEOUT
            )
            if resp.status_code == 200:
                return resp.json()
            return {'error': f'AbuseIPDB returned HTTP {resp.status_code}', 'detail': resp.text[:300]}
        except requests.RequestException as exc:
            return {'error': f'AbuseIPDB request failed: {exc}'}

    @staticmethod
    def extract_score(abuse_response):
        """Returns the abuseConfidenceScore (0-100), or -1 if unavailable."""
        if 'error' in abuse_response:
            return -1
        try:
            return abuse_response['data']['abuseConfidenceScore']
        except (KeyError, TypeError):
            return -1
