"""Tiny HTTP session for router web APIs: cookies, default headers, timeouts, self-signed TLS on the LAN."""
from __future__ import annotations

import http.cookiejar
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

UA = "network-doctor (+https://github.com/dav-ayman/network-doctor)"


class Response:
    def __init__(self, status: int, headers: Dict[str, str], body: bytes, url: str):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.text)

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


class Session:
    """Cookie-keeping session bound to one router base URL (e.g. "http://192.168.1.1").

    TLS verification is off on purpose: home routers use self-signed certificates and the
    session only ever talks to the LAN gateway the user pointed it at.
    """

    def __init__(self, base: str, timeout: float = 15.0, headers: Optional[Dict[str, str]] = None):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ctx), _NoRedirect()
        )
        self.headers = {"User-Agent": UA}
        if headers:
            self.headers.update(headers)

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.base).hostname or ""

    def url(self, path: str) -> str:
        return path if path.startswith(("http://", "https://")) else self.base + (path if path.startswith("/") else "/" + path)

    def request(self, method: str, path: str, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None,
                timeout: Optional[float] = None) -> Response:
        h = dict(self.headers)
        if headers:
            h.update(headers)
        req = urllib.request.Request(self.url(path), data=data, headers=h, method=method)
        try:
            r = self._opener.open(req, timeout=timeout or self.timeout)
            return Response(r.status, dict(r.headers.items()), r.read(), r.geturl())
        except urllib.error.HTTPError as e:  # routers answer 401/404/302 as part of normal flows
            return Response(e.code, dict(e.headers.items()) if e.headers else {}, e.read() or b"", req.full_url)

    def get(self, path: str, **kw: Any) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Any = None, content_type: str = "application/x-www-form-urlencoded; charset=UTF-8",
             **kw: Any) -> Response:
        if isinstance(body, dict):
            data = urllib.parse.urlencode(body).encode()
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = body or b""
        headers = dict(kw.pop("headers", None) or {})
        headers.setdefault("Content-Type", content_type)
        return self.request("POST", path, data=data, headers=headers, **kw)

    def post_json(self, path: str, obj: Any, **kw: Any) -> Response:
        return self.post(path, json.dumps(obj), content_type="application/json;charset=UTF-8", **kw)

    def set_cookie(self, name: str, value: str) -> None:
        self.jar.set_cookie(http.cookiejar.Cookie(
            0, name, value, None, False, self.host, False, False, "/", True, False, None, False, None, None, {}))

    def cookie(self, name: str) -> Optional[str]:
        for c in self.jar:
            if c.name == name:
                return c.value
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep 30x responses visible: several routers signal "not logged in" with a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def first_reachable(host: str, timeout: float = 4.0) -> Tuple[Optional[str], Optional[Response]]:
    """Try http then https on the host; return (base, response of "/") for the first that answers."""
    for scheme in ("http", "https"):
        s = Session(f"{scheme}://{host}", timeout=timeout)
        try:
            r = s.get("/")
        except Exception:
            continue
        if r.status in (301, 302, 303, 307, 308):
            loc = r.header("Location") or ""
            if loc.startswith("https://") and scheme == "http":
                continue
        return s.base, r
    return None, None
