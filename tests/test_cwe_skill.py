from conftest import SAMPLE_VULN, FakeResponse
from vulnmcp.skills import cwe


def test_get_recent_vulnerabilities_by_cwe_normalizes_id(fake_session):
    session = fake_session(FakeResponse([SAMPLE_VULN] * 5))
    results = cwe.get_recent_vulnerabilities_by_cwe(" 79 ")
    assert session.calls[0]["params"]["cwe"] == "CWE-79"
    assert len(results) == 3  # capped at 3
    assert results[0] == {
        "title": "Example RCE",
        "description": "Remote code execution in Example.",
        "vendor_product": "ExampleCorp / Example",
        "link": "https://vulnerability.circl.lu/vuln/CVE-2025-1234",
    }


def test_get_recent_vulnerabilities_by_cwe_defaults(fake_session):
    fake_session(FakeResponse([{}]))
    results = cwe.get_recent_vulnerabilities_by_cwe("CWE-79")
    assert results == [
        {
            "title": "No title available",
            "description": "No description available",
            "vendor_product": "Unknown Vendor/Product",
            "link": "https://vulnerability.circl.lu/vuln/Unknown",
        }
    ]
