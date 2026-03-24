from fastmcp import FastMCP

from vulnmcp.skills import cwe, severity, vulnerability_lookup

mcp = FastMCP(
    name="VulnMCP",
    instructions=(
        "VulnMCP provides AI-driven vulnerability management tools. "
        "Use classify_severity to assess criticality from a description "
        "(English or Chinese). Use classify_cwe to identify the CWE category, "
        "and get_recent_vulnerabilities_by_cwe to fetch recent CVEs for a CWE. "
        "Use get_vulnerability to look up a specific CVE, or search_vulnerabilities "
        "to find vulnerabilities by source, CWE, product, or date."
    ),
)

severity.register(mcp)
cwe.register(mcp)
vulnerability_lookup.register(mcp)


def main() -> None:
    mcp.run()
