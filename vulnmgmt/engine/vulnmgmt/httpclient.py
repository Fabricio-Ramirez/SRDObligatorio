"""Minimal JSON-over-HTTPS client built on urllib (no third-party packages)."""

import base64
import json
import ssl
import urllib.error
import urllib.request


class HTTPError(Exception):
    """Raised for transport errors and non-2xx answers."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def ssl_context(verify=True, ca_file=None):
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=ca_file or None)


class Client:
    """Small JSON client.

    local=True ignores proxy environment variables: Wazuh, the indexer and
    Ollama run on the same server and must never be reached through a proxy.
    """

    def __init__(self, base_url, verify=True, ca_file=None, timeout=30,
                 username=None, password=None, local=False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = {"Accept": "application/json"}
        if username is not None:
            token = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        handlers = [urllib.request.HTTPSHandler(context=ssl_context(verify, ca_file))]
        if local:
            handlers.append(urllib.request.ProxyHandler({}))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, method, path, body=None, headers=None, raw=False):
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        data = None
        hdrs = dict(self.headers)
        hdrs.update(headers or {})
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read(300).decode(errors="replace")
            raise HTTPError(f"{method} {url} -> HTTP {exc.code}: {detail}", exc.code) from None
        except (urllib.error.URLError, OSError) as exc:
            raise HTTPError(f"{method} {url} -> {exc}") from None
        if raw:
            return payload
        try:
            return json.loads(payload or b"null")
        except ValueError:
            raise HTTPError(f"{method} {url} -> invalid JSON answer") from None
