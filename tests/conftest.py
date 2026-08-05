"""Shared test fixtures.

Everything here is offline. A scanner's test suite must never emit a real
request, so we drive the engine with a `FakeSession` that answers from canned
routes instead of the network.
"""

from __future__ import annotations

import json as _json

import pytest


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status_code=200, json_data=None, text=None, headers=None, content=None):
        self.status_code = status_code
        self._json = json_data
        if text is not None:
            self.text = text
        elif json_data is not None:
            self.text = _json.dumps(json_data)
        else:
            self.text = ""
        self.headers = headers or {}
        self.content = content if content is not None else self.text.encode()

    def json(self):
        if self._json is None:
            raise ValueError("response has no JSON body")
        return self._json


def resp(status_code=200, **kw):
    return FakeResponse(status_code=status_code, **kw)


class FakeSession:
    """Routes requests by (method, url-substring). First matching rule wins.

    rules: list of (method, substring, FakeResponse|None). method "*" matches any
    verb; a None response models a dropped connection.
    """

    def __init__(self, rules=None, default=None):
        self.rules = rules or []
        self.default = default if default is not None else FakeResponse(404, text="not found")
        self.verify = True
        self.calls: list[tuple[str, str]] = []

    def _match(self, method, url):
        for m, substr, r in self.rules:
            if m in (method, "*") and substr in url:
                return r
        return self.default

    def get(self, url, **kw):
        self.calls.append(("GET", url))
        return self._match("GET", url)

    def post(self, url, **kw):
        self.calls.append(("POST", url))
        return self._match("POST", url)


@pytest.fixture
def fake_session():
    return FakeSession


@pytest.fixture
def base_ctx():
    """A ctx pre-seeded past the ENDPOINT stage."""
    return {"base": "https://target:8880", "active": False}


@pytest.fixture
def snake_tmp_home(tmp_path, monkeypatch):
    """Redirect report output into a temp dir so tests never touch ~/.snake."""
    monkeypatch.setenv("SNAKE_HOME", str(tmp_path))
    return tmp_path
