import asyncio

from vulnmcp import server

EXPECTED_TOOLS = {
    "classify_severity",
    "classify_cwe",
    "classify_attack_techniques",
    "get_recent_vulnerabilities_by_cwe",
    "get_vulnerability",
    "search_vulnerabilities",
    "search_sightings",
    "create_sighting",
    "get_most_sighted_vulnerabilities",
    "list_kev_entries",
    "search_comments",
    "search_bundles",
    "guess_cpes",
    "list_gna_entries",
    "get_gna_entry",
    "search_gna",
    "list_gcve_references",
    "search_cna_partners",
    "get_cna_partner",
}


def test_all_tools_registered():
    tools = asyncio.run(server.mcp.list_tools())
    assert {t.name for t in tools} == EXPECTED_TOOLS


def test_instructions_mention_every_tool():
    """Every tool name appears in the server instructions built from the skills."""
    instructions = server.mcp.instructions
    for name in EXPECTED_TOOLS:
        assert name in instructions, f"{name} missing from server instructions"


def test_tool_annotations():
    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
    # create_sighting is the only tool that writes
    assert tools["create_sighting"].annotations.readOnlyHint is False
    read_only = EXPECTED_TOOLS - {"create_sighting"}
    for name in read_only:
        assert tools[name].annotations.readOnlyHint is True, name
