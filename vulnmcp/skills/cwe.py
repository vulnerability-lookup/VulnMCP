from fastmcp import FastMCP

from vulnmcp.skills.vulnerability_lookup import _base_url, _get_session


def register(mcp: FastMCP) -> None:
    """Register CWE lookup tools on the MCP server."""

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        }
    )
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

        response = _get_session().get(
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
