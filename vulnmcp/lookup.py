"""Shared HTTP layer for the Vulnerability Lookup and cpe-guesser APIs.

Every skill that talks to a Vulnerability Lookup instance goes through
this module: it owns the base URLs, the authenticated session, the
PyVulnerabilityLookup client, and the helpers that reshape raw API
payloads into the summaries the tools return.
"""

import os
from importlib.metadata import version

import requests
from pyvulnerabilitylookup import PyVulnerabilityLookup

DEFAULT_BASE_URL = "https://vulnerability.circl.lu"
DEFAULT_CPE_GUESSER_URL = "https://cpe-guesser.cve-search.org"
DEFAULT_SIGHTING_TYPES = [
    "seen",
    "exploited",
    "not exploited",
    "confirmed",
    "not confirmed",
    "patched",
    "not patched",
    "published proof of concept",
]

_vulnmcp_version = version("vulnmcp")
USER_AGENT = (
    f"VulnMCP/{_vulnmcp_version} "
    "(+https://github.com/vulnerability-lookup/VulnMCP)"
)

_session: requests.Session | None = None
_client: PyVulnerabilityLookup | None = None


def base_url() -> str:
    return os.environ.get("VULNMCP_LOOKUP_URL", DEFAULT_BASE_URL).rstrip("/")


def cpe_guesser_url() -> str:
    return os.environ.get(
        "VULNMCP_CPE_GUESSER_URL", DEFAULT_CPE_GUESSER_URL
    ).rstrip("/")


def get_client() -> PyVulnerabilityLookup:
    global _client
    if _client is None:
        token = os.environ.get("VULNMCP_API_KEY", "").strip() or None
        _client = PyVulnerabilityLookup(
            root_url=base_url(),
            useragent=USER_AGENT,
            token=token,
        )
    return _client


def get_session() -> requests.Session:
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers["User-Agent"] = USER_AGENT
    api_key = os.environ.get("VULNMCP_API_KEY", "").strip()
    if api_key:
        _session.headers["X-API-KEY"] = api_key
    elif "X-API-KEY" in _session.headers:
        _session.headers.pop("X-API-KEY", None)
    return _session


def normalize_payload(payload) -> tuple[list, dict]:
    """Split an API response into (data, metadata), whatever its shape.

    The Vulnerability Lookup endpoints return either a paginated dict
    ({"data": [...], "metadata": {...}}) or a bare list.
    """
    if isinstance(payload, dict):
        data = payload.get("data", [])
        metadata = payload.get("metadata", {})
    elif isinstance(payload, list):
        data = payload
        metadata = {}
    else:
        data = []
        metadata = {}
    if not isinstance(data, list):
        data = []
    return data, metadata


def extract_summary(vuln: dict) -> dict:
    """Extract a human-readable summary from a raw vulnerability record."""
    cna = vuln.get("containers", {}).get("cna", {})
    metadata = vuln.get("cveMetadata", {})

    vuln_id = metadata.get("cveId", "Unknown")

    # Title
    title = cna.get("title", "")

    # Description — prefer English
    descriptions = cna.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang", "").startswith("en"):
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # Affected products
    affected = cna.get("affected", [])
    products = []
    for a in affected:
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        entry = f"{vendor} / {product}" if vendor and product else vendor or product
        if entry:
            products.append(entry)

    # CVSS scores from metrics
    cvss_scores = []
    for metric_block in cna.get("metrics", []):
        for key, val in metric_block.items():
            if key.startswith("cvss") and isinstance(val, dict):
                score = val.get("baseScore")
                severity = val.get("baseSeverity", "")
                version = val.get("version", "")
                if score is not None:
                    cvss_scores.append({
                        "version": version,
                        "score": score,
                        "severity": severity,
                    })

    # CWE from problemTypes
    cwes = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId", "")
            if cwe_id:
                cwes.append(cwe_id)

    # References
    references = [
        ref.get("url") for ref in cna.get("references", []) if ref.get("url")
    ]

    # Dates
    dates = {}
    for key in ("datePublished", "dateUpdated", "dateReserved"):
        if metadata.get(key):
            dates[key] = metadata[key]

    return {
        "id": vuln_id,
        "title": title,
        "description": description,
        "affected_products": products,
        "cvss": cvss_scores,
        "cwes": cwes,
        "references": references,
        "dates": dates,
        "link": f"{base_url()}/vuln/{vuln_id}",
    }


def get_kev_for_vulnerability(
    vulnerability_id: str,
    vulnerability_lookup_origin: str | None = None,
) -> dict:
    """Query /api/kev to check whether a vulnerability appears in any KEV catalog."""
    vuln_id = vulnerability_id.upper().strip()

    params: dict = {"vuln_id": vuln_id, "per_page": "100"}
    if vulnerability_lookup_origin:
        params["vulnerability_lookup_origin"] = vulnerability_lookup_origin.strip()

    try:
        response = get_session().get(
            f"{base_url()}/api/kev",
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException:
        return {"in_kev": False, "entries": []}

    items, _ = normalize_payload(data)

    return {
        "in_kev": len(items) > 0,
        "entries": items,
    }


def fetch_kev_list(
    vuln_id: str | None = None,
    status_reason: str | None = None,
    exploited: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    author: str | None = None,
    vulnerability_lookup_origin: str | None = None,
    per_page: int = 10,
    page: int = 1,
) -> dict:
    """Fetch KEV entries from /api/kev with optional filters."""
    params: dict = {
        "per_page": str(min(per_page, 1000)),
        "page": str(page),
    }
    if vuln_id:
        params["vuln_id"] = vuln_id.upper().strip()
    if status_reason:
        params["status_reason"] = status_reason
    if exploited is not None:
        params["exploited"] = str(exploited).lower()
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to
    if author:
        params["author"] = author
    if vulnerability_lookup_origin:
        params["vulnerability_lookup_origin"] = vulnerability_lookup_origin.strip()

    response = get_session().get(
        f"{base_url()}/api/kev",
        params=params,
        timeout=15,
    )
    response.raise_for_status()
    return response.json()
