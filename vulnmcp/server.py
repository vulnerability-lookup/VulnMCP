from fastmcp import FastMCP

from vulnmcp.models import ML_AVAILABLE
from vulnmcp.skills import cwe, gcve, vulnerability_lookup

_BASE_INSTRUCTIONS = (
    "VulnMCP provides AI-driven vulnerability management tools. "
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
    "to explore the GCVE Global Numbering Authority registry and references. "
    "Use get_recent_vulnerabilities_by_cwe to fetch recent CVEs for a CWE."
)

_ML_INSTRUCTIONS = (
    " Use classify_severity to assess criticality from a description "
    "(English, Chinese, or Russian). Use classify_cwe to identify the CWE category."
)

mcp = FastMCP(
    name="VulnMCP",
    instructions=_BASE_INSTRUCTIONS + (_ML_INSTRUCTIONS if ML_AVAILABLE else ""),
)

vulnerability_lookup.register(mcp)
cwe.register(mcp)
gcve.register(mcp)

if ML_AVAILABLE:
    from vulnmcp.skills import severity
    severity.register(mcp)


def main() -> None:
    mcp.run()
