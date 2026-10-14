"""Authenticated JSON client; credentials never follow redirects."""
import ipaddress
import json
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def validate_url(url):
    parsed = urlparse(url)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('URL must have a hostname and no credentials, query or fragment')
    if parsed.scheme == 'https':
        return parsed
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == 'localhost'
    if parsed.scheme != 'http' or not loopback:
        raise ValueError('HTTPS is required except for loopback development')
    return parsed


class Client:
    def __init__(self, url, token, timeout=10):
        validate_url(url)
        self.url, self.token, self.timeout = url.rstrip('/'), token, timeout
        # Tailnet calls must not leak credentials to ambient HTTP proxies.
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = Request(self.url + path, data=data, headers={
            'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=self.timeout) as response:
            payload = response.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise ValueError('response too large')
            return json.loads(payload)
