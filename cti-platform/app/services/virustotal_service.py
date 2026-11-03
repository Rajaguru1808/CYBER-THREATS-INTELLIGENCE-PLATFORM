"""
VirusTotal API v3 integration.
Docs: https://developer.virustotal.com/reference/overview
"""
import requests
from flask import current_app

BASE_URL = 'https://www.virustotal.com/api/v3'
TIMEOUT = 15


class VirusTotalService:
    def __init__(self, api_key=None):
        self.api_key = api_key or current_app.config.get('VIRUSTOTAL_API_KEY')

    def _headers(self):
        return {'x-apikey': self.api_key}

    def _request(self, endpoint):
        if not self.api_key:
            return {'error': 'VirusTotal API key is not configured.'}
        try:
            resp = requests.get(f'{BASE_URL}{endpoint}', headers=self._headers(), timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            return {'error': f'VirusTotal returned HTTP {resp.status_code}', 'detail': resp.text[:300]}
        except requests.RequestException as exc:
            return {'error': f'VirusTotal request failed: {exc}'}

    def lookup_ip(self, ip):
        return self._request(f'/ip_addresses/{ip}')

    def lookup_domain(self, domain):
        return self._request(f'/domains/{domain}')

    def lookup_url(self, url_id):
        # VT requires a URL identifier (base64 url-safe, no padding) for lookups
        import base64
        encoded = base64.urlsafe_b64encode(url_id.encode()).decode().strip('=')
        return self._request(f'/urls/{encoded}')

    def lookup_hash(self, file_hash):
        return self._request(f'/files/{file_hash}')

    @staticmethod
    def extract_reputation(vt_response):
        """Normalize a VT response into a simple reputation summary."""
        if 'error' in vt_response:
            return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'error': vt_response['error']}
        try:
            stats = vt_response['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
            }
        except (KeyError, TypeError):
            return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'error': 'Unexpected response format'}
