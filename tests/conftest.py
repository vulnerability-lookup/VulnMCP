import pytest
import requests

from vulnmcp import lookup


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    """Reset lookup's cached session/client and clear VulnMCP env overrides."""
    monkeypatch.setattr(lookup, "_session", None)
    monkeypatch.setattr(lookup, "_client", None)
    for var in ("VULNMCP_LOOKUP_URL", "VULNMCP_CPE_GUESSER_URL", "VULNMCP_API_KEY"):
        monkeypatch.delenv(var, raising=False)


class FakeResponse:
    def __init__(self, json_data, status_code: int = 200):
        self._json = json_data
        self.status_code = status_code

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    """Stands in for requests.Session; queues responses and records calls."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def _next(self, method, url, kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError(f"unexpected {method} request to {url}")
        return self.responses.pop(0)

    def get(self, url, **kwargs):
        return self._next("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._next("POST", url, kwargs)


@pytest.fixture
def fake_session(monkeypatch):
    """Patch lookup.get_session with a FakeSession the test can inspect."""

    def _install(*responses) -> FakeSession:
        session = FakeSession(*responses)
        monkeypatch.setattr(lookup, "get_session", lambda: session)
        return session

    return _install


# A raw record in the shape the Vulnerability Lookup API returns.
SAMPLE_VULN = {
    "cveMetadata": {
        "cveId": "CVE-2025-1234",
        "datePublished": "2025-06-01T00:00:00Z",
        "dateUpdated": "2025-06-02T00:00:00Z",
    },
    "containers": {
        "cna": {
            "title": "Example RCE",
            "descriptions": [
                {"lang": "fr", "value": "Description française"},
                {"lang": "en", "value": "Remote code execution in Example."},
            ],
            "affected": [
                {"vendor": "ExampleCorp", "product": "Example"},
                {"vendor": "", "product": "OtherProduct"},
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "version": "3.1",
                    },
                    "other": {"not": "a cvss block"},
                }
            ],
            "problemTypes": [
                {"descriptions": [{"cweId": "CWE-79"}, {"description": "no id"}]}
            ],
            "references": [
                {"url": "https://example.com/advisory"},
                {"name": "no url"},
            ],
        }
    },
}
