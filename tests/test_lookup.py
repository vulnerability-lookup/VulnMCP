import requests

from conftest import SAMPLE_VULN, FakeResponse
from vulnmcp import lookup


def test_base_url_default():
    assert lookup.base_url() == "https://vulnerability.circl.lu"


def test_base_url_env_override_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("VULNMCP_LOOKUP_URL", "https://vl.example.org/")
    assert lookup.base_url() == "https://vl.example.org"


def test_cpe_guesser_url_env_override(monkeypatch):
    monkeypatch.setenv("VULNMCP_CPE_GUESSER_URL", "https://guess.example.org/")
    assert lookup.cpe_guesser_url() == "https://guess.example.org"


def test_get_session_sets_user_agent_and_api_key(monkeypatch):
    session = lookup.get_session()
    assert session.headers["User-Agent"].startswith("VulnMCP/")
    assert "X-API-KEY" not in session.headers

    monkeypatch.setenv("VULNMCP_API_KEY", "secret")
    assert lookup.get_session().headers["X-API-KEY"] == "secret"

    # Key removed again once the variable is unset
    monkeypatch.delenv("VULNMCP_API_KEY")
    assert "X-API-KEY" not in lookup.get_session().headers


def test_normalize_payload_shapes():
    assert lookup.normalize_payload({"data": [1], "metadata": {"m": 1}}) == (
        [1],
        {"m": 1},
    )
    assert lookup.normalize_payload([1, 2]) == ([1, 2], {})
    assert lookup.normalize_payload(None) == ([], {})
    assert lookup.normalize_payload({"data": "not a list"}) == ([], {})


def test_extract_summary_full_record():
    summary = lookup.extract_summary(SAMPLE_VULN)
    assert summary["id"] == "CVE-2025-1234"
    assert summary["title"] == "Example RCE"
    # English description preferred over the first (French) one
    assert summary["description"] == "Remote code execution in Example."
    assert summary["affected_products"] == ["ExampleCorp / Example", "OtherProduct"]
    assert summary["cvss"] == [
        {"version": "3.1", "score": 9.8, "severity": "CRITICAL"}
    ]
    assert summary["cwes"] == ["CWE-79"]
    assert summary["references"] == ["https://example.com/advisory"]
    assert summary["dates"] == {
        "datePublished": "2025-06-01T00:00:00Z",
        "dateUpdated": "2025-06-02T00:00:00Z",
    }
    assert summary["link"] == "https://vulnerability.circl.lu/vuln/CVE-2025-1234"


def test_extract_summary_falls_back_to_first_description():
    vuln = {
        "containers": {
            "cna": {"descriptions": [{"lang": "fr", "value": "Seulement français"}]}
        }
    }
    summary = lookup.extract_summary(vuln)
    assert summary["id"] == "Unknown"
    assert summary["description"] == "Seulement français"


def test_extract_summary_empty_record():
    summary = lookup.extract_summary({})
    assert summary["id"] == "Unknown"
    assert summary["affected_products"] == []
    assert summary["cvss"] == []


def test_get_kev_for_vulnerability_found(fake_session):
    session = fake_session(FakeResponse({"data": [{"vuln_id": "CVE-2021-44228"}]}))
    result = lookup.get_kev_for_vulnerability("cve-2021-44228")
    assert result["in_kev"] is True
    assert len(result["entries"]) == 1
    call = session.calls[0]
    assert call["url"].endswith("/api/kev")
    assert call["params"]["vuln_id"] == "CVE-2021-44228"


def test_get_kev_for_vulnerability_swallows_request_errors(monkeypatch):
    class FailingSession:
        def get(self, *args, **kwargs):
            raise requests.ConnectionError("down")

    monkeypatch.setattr(lookup, "get_session", lambda: FailingSession())
    assert lookup.get_kev_for_vulnerability("CVE-2025-1") == {
        "in_kev": False,
        "entries": [],
    }


def test_fetch_kev_list_builds_params(fake_session):
    session = fake_session(FakeResponse({"data": []}))
    lookup.fetch_kev_list(
        vuln_id="cve-2025-1",
        status_reason="confirmed",
        exploited=True,
        date_from="2025-01-01",
        author="alice",
        per_page=5000,
        page=2,
    )
    params = session.calls[0]["params"]
    assert params["vuln_id"] == "CVE-2025-1"
    assert params["status_reason"] == "confirmed"
    assert params["exploited"] == "true"
    assert params["date_from"] == "2025-01-01"
    assert params["author"] == "alice"
    assert params["per_page"] == "1000"  # capped
    assert params["page"] == "2"
    assert "date_to" not in params
    assert "vulnerability_lookup_origin" not in params
