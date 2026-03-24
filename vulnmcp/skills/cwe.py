import requests
from fastmcp import FastMCP

from vulnmcp.models.classifier import CWEClassifier
from vulnmcp.skills.vulnerability_lookup import _base_url


def register(mcp: FastMCP) -> None:
    """Register CWE classification and lookup tools on the MCP server."""

    classifier = CWEClassifier()

    @mcp.tool
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
        return classifier.classify(description)

    @mcp.tool
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

        response = requests.get(
            f"{_base_url()}/api/vulnerability/",
            params={
                "source": "cvelistv5",
                "cwe": cwe_id,
                "sort_order": "desc",
                "date_sort": "published",
            },
            timeout=15,
        )
        response.raise_for_status()

        vulnerabilities = response.json()
        results = []

        for vuln in vulnerabilities[:3]:
            title = vuln.get("title", "No title available")

            descriptions = (
                vuln.get("containers", {})
                .get("cna", {})
                .get("descriptions", [])
            )
            description = (
                descriptions[0].get("value")
                if descriptions
                else "No description available"
            )

            affected = (
                vuln.get("containers", {}).get("cna", {}).get("affected", [])
            )
            if affected:
                vendor = affected[0].get("vendor", "Unknown Vendor")
                product = affected[0].get("product", "Unknown Product")
                vendor_product = f"{vendor} / {product}"
            else:
                vendor_product = "Unknown Vendor/Product"

            cve_id = vuln.get("cveMetadata", {}).get("cveId", "Unknown CVE")
            link = f"{_base_url()}/vuln/{cve_id}"

            results.append({
                "title": title,
                "description": description,
                "vendor_product": vendor_product,
                "link": link,
            })

        return results
