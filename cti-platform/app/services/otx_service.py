"""
AlienVault OTX (Open Threat Exchange) API integration.
Docs: https://otx.alienvault.com/api
"""
import requests
from flask import current_app

BASE_URL = 'https://otx.alienvault.com/api/v1'
TIMEOUT = 15


class OTXService:
    def __init__(self, api_key=None):
        self.api_key = api_key or current_app.config.get('OTX_API_KEY')

    def _headers(self):
        return {'X-OTX-API-KEY': self.api_key}

    def _request(self, endpoint):
        if not self.api_key:
            return {'error': 'AlienVault OTX API key is not configured.'}
        try:
            resp = requests.get(f'{BASE_URL}{endpoint}', headers=self._headers(), timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            return {'error': f'OTX returned HTTP {resp.status_code}', 'detail': resp.text[:300]}
        except requests.RequestException as exc:
            return {'error': f'OTX request failed: {exc}'}

    def lookup_ip(self, ip):
        return self._request(f'/indicators/IPv4/{ip}/general')

    def lookup_domain(self, domain):
        return self._request(f'/indicators/domain/{domain}/general')

    def lookup_hostname(self, hostname):
        return self._request(f'/indicators/hostname/{hostname}/general')

    def lookup_url(self, url):
        import urllib.parse
        encoded = urllib.parse.quote(url, safe='')
        return self._request(f'/indicators/url/{encoded}/general')

    def lookup_hash(self, file_hash):
        return self._request(f'/indicators/file/{file_hash}/general')

    def get_subscribed_pulses(self, limit=20):
        return self._request(f'/pulses/subscribed?limit={limit}')

    @staticmethod
    def extract_pulse_count(otx_response):
        """Number of threat-intel 'pulses' referencing this indicator - a rough
        popularity/severity signal."""
        if 'error' in otx_response:
            return 0
        return otx_response.get('pulse_info', {}).get('count', 0)
