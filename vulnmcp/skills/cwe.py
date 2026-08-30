from fastmcp import FastMCP

from vulnmcp import lookup
from vulnmcp.models.classifier import CWEClassifier

INSTRUCTIONS = (
    "Use classify_cwe to identify the CWE category, "
    "and get_recent_vulnerabilities_by_cwe to fetch recent CVEs for a CWE."
)

_classifier = CWEClassifier()


def classify_cwe(description: str) -> dict:
    """Classify a vulnerability description into CWE categories.

    Uses CIRCL's fine-tuned RoBERTa model to predict the most likely
    CWE (Common Weakness Enumeration) categories, mapped to their
    parent CWEs.

    Args:
        description: The vulnerability description text (English).

    Returns:
        A dict with: primary_cwe, confidence, predictions (top 5), model.
    """
    return _classifier.classify(description)


def get_recent_vulnerabilities_by_cwe(cwe_id: str) -> list[dict]:
    """Fetch the 3 most recent vulnerabilities for a given CWE ID from Vulnerability Lookup.

    Args:
        cwe_id: The CWE identifier (e.g. "CWE-79" or "79").

    Returns:
        A list of dicts with: title, description, vendor_product, link.
    """
    # Normalize to "CWE-XXX" format
    cwe_id = cwe_id.strip().upper()
    if not cwe_id.startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"

    response = lookup.get_session().get(
        f"{lookup.base_url()}/api/vulnerability/",
        params={
            "source": "cvelistv5",
            "cwe": cwe_id,
            "sort_order": "desc",
            "date_sort": "published",
        },
        timeout=15,
    )
    response.raise_for_status()

    results = []
    for vuln in response.json()[:3]:
        summary = lookup.extract_summary(vuln)
        products = summary["affected_products"]
        results.append({
            "title": summary["title"] or "No title available",
            "description": summary["description"] or "No description available",
            "vendor_product": products[0] if products else "Unknown Vendor/Product",
            "link": summary["link"],
        })

    return results


def register(mcp: FastMCP) -> None:
    """Register CWE classification and lookup tools on the MCP server."""
    mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )(classify_cwe)

    mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        }
    )(get_recent_vulnerabilities_by_cwe)
