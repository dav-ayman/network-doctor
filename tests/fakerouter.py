"""Test helpers: put the skill's scripts on sys.path and fake a router's HTTP API from fixtures.

Usage in a test:
    from tests.fakerouter import FakeSession, fixture
    d = SomeDriver("http://192.0.2.1")
    d.s = FakeSession(d.s, {("GET", "/api/x"): fixture("family/x.xml"), ("POST", "/login"): (200, '{"ok":1}', {})})
Keys are (METHOD, path-with-query) or (METHOD, path-prefix + "*"). Values are a body string, or
(status, body, headers), or a callable(method, path, data, headers) returning one of those.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "plugins", "network-doctor", "skills", "network-doctor", "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from netdoc.web import Response  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(rel: str) -> str:
    with open(os.path.join(FIXTURES, rel), encoding="utf-8") as f:
        return f.read()


class FakeSession:
    """Drop-in for netdoc.web.Session that answers from a routing table and records every request."""

    def __init__(self, real, routes):
        self._real = real
        self.routes = dict(routes)
        self.calls = []  # (method, path, data, headers)

    def __getattr__(self, name):  # base, headers, host, jar, set_cookie, cookie, url ...
        return getattr(self._real, name)

    def _answer(self, method, path, data, headers):
        self.calls.append((method, path, data, headers))
        key = (method, path)
        v = self.routes.get(key)
        if v is None:
            for (m, p), val in self.routes.items():
                if m == method and p.endswith("*") and path.startswith(p[:-1]):
                    v = val
                    break
        if v is None:
            return Response(404, {}, b"not found", path)
        if callable(v):
            v = v(method, path, data, headers)
        if isinstance(v, str):
            v = (200, v, {})
        status, body, hdrs = v
        return Response(status, hdrs, body.encode() if isinstance(body, str) else body, path)

    def request(self, method, path, data=None, headers=None, timeout=None):
        if isinstance(data, str):
            data = data.encode()
        return self._answer(method, path, data, headers or {})

    def get(self, path, **kw):
        return self.request("GET", path, headers=kw.get("headers"))

    def post(self, path, body=None, content_type="", **kw):
        from urllib.parse import urlencode
        if isinstance(body, dict):
            data = urlencode(body).encode()
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = body or b""
        return self.request("POST", path, data=data, headers=kw.get("headers"))

    def post_json(self, path, obj, **kw):
        import json as _json
        return self.request("POST", path, data=_json.dumps(obj).encode(), headers=kw.get("headers"))
