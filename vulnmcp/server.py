from fastmcp import FastMCP

from vulnmcp.skills import attack, cwe, gcve, severity, vulnerability_lookup

mcp = FastMCP(
    name="VulnMCP",
    instructions=(
        "VulnMCP provides AI-driven vulnerability management tools. "
        "Use classify_severity to assess criticality from a description "
        "(English, Chinese, or Russian). Use classify_cwe to identify the CWE category, "
        "and get_recent_vulnerabilities_by_cwe to fetch recent CVEs for a CWE. "
        "Use classify_attack_techniques to predict MITRE ATT&CK techniques "
        "from a vulnerability description. "
        "Use get_vulnerability to look up a specific CVE, or search_vulnerabilities "
        "to find vulnerabilities by source, CWE, product, or date. "
        "Use search_sightings, create_sighting, and get_most_sighted_vulnerabilities "
        "to prioritize vulnerabilities based on real-world sighting activity. "
        "Use search_comments to find community comments related to a vulnerability, "
        "and search_bundles to find curated vulnerability bundles. "
        "Use list_kev_entries to browse, filter, or check Known Exploited "
        "Vulnerability (KEV) catalog entries. "
        "Use guess_cpes to infer likely CPE identifiers from product keywords. "
        "Use list_gna_entries, get_gna_entry, search_gna, and list_gcve_references "
        "to explore the GCVE Global Numbering Authority registry and references."
    ),
)

severity.register(mcp)
cwe.register(mcp)
attack.register(mcp)
vulnerability_lookup.register(mcp)
gcve.register(mcp)


def main() -> None:
    mcp.run()
