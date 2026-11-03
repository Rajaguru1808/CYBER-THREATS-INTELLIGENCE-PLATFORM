"""
MISP integration service, built on PyMISP.

This wraps all PyMISP calls so the rest of the app never touches the
PyMISP library directly. If MISP is unreachable or PyMISP isn't installed,
methods fail gracefully and return an error dict instead of raising, so the
UI can degrade gracefully (e.g. hide MISP-backed features).
"""
from flask import current_app

try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
    PYMISP_AVAILABLE = True
except ImportError:  # pymisp not installed in this environment
    PYMISP_AVAILABLE = False


class MISPService:
    """Thin wrapper around PyMISP for event/attribute CRUD and searching."""

    def __init__(self, url=None, api_key=None, verify_ssl=None):
        self.url = url or current_app.config.get('MISP_URL')
        self.api_key = api_key or current_app.config.get('MISP_API_KEY')
        self.verify_ssl = verify_ssl if verify_ssl is not None else current_app.config.get('MISP_VERIFY_SSL')
        self._client = None

    def _get_client(self):
        if not PYMISP_AVAILABLE:
            raise RuntimeError('pymisp package is not installed. Run: pip install pymisp')
        if not self.url or not self.api_key:
            raise RuntimeError('MISP URL / API key not configured. Set them in Settings.')
        if self._client is None:
            self._client = PyMISP(self.url, self.api_key, self.verify_ssl)
        return self._client

    def test_connection(self):
        """Returns (True, version_info) or (False, error_message)."""
        try:
            client = self._get_client()
            info = client.misp_instance_version
            return True, info
        except Exception as exc:  # noqa: BLE001 - surface any failure to caller
            return False, str(exc)

    def create_event(self, title, description, threat_level='medium', distribution='0'):
        """Create a new event on the connected MISP instance.

        threat_level mapping to MISP numeric levels: 1=High 2=Medium 3=Low 4=Undefined
        """
        level_map = {'critical': '1', 'high': '1', 'medium': '2', 'low': '3'}
        client = self._get_client()
        event = MISPEvent()
        event.info = title
        event.distribution = distribution
        event.threat_level_id = level_map.get(threat_level, '2')
        event.analysis = 0
        if description:
            event.add_attribute('comment', description)
        result = client.add_event(event)
        return result

    def update_event(self, misp_event_id, **fields):
        client = self._get_client()
        event = client.get_event(misp_event_id, pythonify=True)
        for key, value in fields.items():
            setattr(event, key, value)
        return client.update_event(event)

    def add_attribute(self, misp_event_id, ioc_type, ioc_value, category='Network activity'):
        """Push a single IOC attribute to an existing MISP event."""
        type_map = {
            'ip': 'ip-dst', 'domain': 'domain', 'url': 'url', 'email': 'email-src',
            'hash_md5': 'md5', 'hash_sha1': 'sha1', 'hash_sha256': 'sha256',
        }
        client = self._get_client()
        attribute = MISPAttribute()
        attribute.type = type_map.get(ioc_type, 'other')
        attribute.value = ioc_value
        attribute.category = category
        return client.add_attribute(misp_event_id, attribute)

    def search_attribute(self, value):
        """Search MISP for a matching attribute value (used for correlation)."""
        client = self._get_client()
        return client.search(controller='attributes', value=value)

    def get_events(self, limit=50):
        client = self._get_client()
        return client.search(controller='events', limit=limit, pythonify=True)
