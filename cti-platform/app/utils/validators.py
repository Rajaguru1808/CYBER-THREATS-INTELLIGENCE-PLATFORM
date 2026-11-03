"""
Validation helpers for user input: IOC values (IP/domain/URL/email/hash),
account fields, and generic form data. Keeping validation centralized makes
it easy to reuse across the web forms and the REST API.
"""
import re

IPV4_RE = re.compile(
    r'^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$'
)
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$'
)
URL_RE = re.compile(r'^(https?|ftp)://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
EMAIL_RE = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
MD5_RE = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_RE = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')

USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,50}$')


def is_valid_ip(value):
    return bool(IPV4_RE.match(value.strip()))


def is_valid_domain(value):
    return bool(DOMAIN_RE.match(value.strip()))


def is_valid_url(value):
    return bool(URL_RE.match(value.strip()))


def is_valid_email(value):
    return bool(EMAIL_RE.match(value.strip()))


def is_valid_hash(value, hash_type):
    value = value.strip()
    if hash_type == 'hash_md5':
        return bool(MD5_RE.match(value))
    if hash_type == 'hash_sha1':
        return bool(SHA1_RE.match(value))
    if hash_type == 'hash_sha256':
        return bool(SHA256_RE.match(value))
    return False


def detect_ioc_type(value):
    """Best-effort auto-detection of an IOC's type, used by the search feature."""
    value = value.strip()
    if is_valid_ip(value):
        return 'ip'
    if is_valid_url(value):
        return 'url'
    if is_valid_email(value):
        return 'email'
    if MD5_RE.match(value):
        return 'hash_md5'
    if SHA1_RE.match(value):
        return 'hash_sha1'
    if SHA256_RE.match(value):
        return 'hash_sha256'
    if is_valid_domain(value):
        return 'domain'
    return None


def validate_ioc(ioc_type, ioc_value):
    """Validate that ioc_value matches the format expected for ioc_type.
    Returns (is_valid: bool, error_message: str|None)
    """
    if not ioc_value or not ioc_value.strip():
        return False, 'IOC value cannot be empty.'

    validators = {
        'ip': is_valid_ip,
        'domain': is_valid_domain,
        'url': is_valid_url,
        'email': is_valid_email,
        'hash_md5': lambda v: is_valid_hash(v, 'hash_md5'),
        'hash_sha1': lambda v: is_valid_hash(v, 'hash_sha1'),
        'hash_sha256': lambda v: is_valid_hash(v, 'hash_sha256'),
    }
    validator = validators.get(ioc_type)
    if validator is None:
        return False, f'Unknown IOC type: {ioc_type}'
    if not validator(ioc_value):
        return False, f'"{ioc_value}" is not a valid {ioc_type.replace("_", " ")}.'
    return True, None


def is_valid_username(value):
    return bool(USERNAME_RE.match(value.strip()))


def is_strong_password(value):
    """At least 8 chars, one letter, one number."""
    if len(value) < 8:
        return False
    return bool(re.search(r'[A-Za-z]', value)) and bool(re.search(r'\d', value))
