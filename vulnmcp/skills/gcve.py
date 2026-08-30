from __future__ import annotations

from gcve.cna import (
    CNAPartner,
    find_cna_by_name,
    get_cna_by_country,
    get_cna_by_short_name,
)
from gcve.gna import GNAEntry, find_gna_by_short_name, get_gna, get_gna_by_short_name
from gcve.registry import (
    load_cna_partners,
    load_references,
    load_registry,
    update_cna_partners,
    update_references,
    update_registry,
    update_registry_public_key,
    update_registry_signature,
    verify_registry_integrity,
)
from fastmcp import FastMCP

INSTRUCTIONS = (
    "Use list_gna_entries, get_gna_entry, search_gna, and list_gcve_references "
    "to explore the GCVE Global Numbering Authority registry and references. "
    "Use search_cna_partners to find CNA partners of the CVE Program by name, "
    "country, role, or organization type, and get_cna_partner for one partner's "
    "full record (disclosure policy, advisory links, contacts)."
)


def _ensure_registry() -> list[GNAEntry]:
    """Download (if needed) and return the verified GNA registry."""
    update_registry_public_key()
    update_registry_signature()
    update_registry()
    if not verify_registry_integrity():
        raise RuntimeError("GCVE registry integrity verification failed")
    return load_registry()


def _gna_to_dict(entry: GNAEntry) -> dict:
    return {
        "id": entry["id"],
        "short_name": entry["short_name"],
        "full_name": entry.get("full_name", ""),
        "cpe_vendor_name": entry.get("cpe_vendor_name", ""),
        "gcve_url": entry.get("gcve_url", ""),
        "gcve_api": entry.get("gcve_api", ""),
        "gcve_dump": entry.get("gcve_dump", ""),
        "gcve_allocation": entry.get("gcve_allocation", ""),
        "gcve_pull_api": entry.get("gcve_pull_api", ""),
    }


def list_gna_entries() -> dict:
    """List all Global Numbering Authorities (GNA) from the GCVE registry.

    Downloads and verifies the registry if not already cached locally.

    Returns:
        A dict with the total count and list of all GNA entries, each
        containing id, short_name, full_name, cpe_vendor_name, and URLs.
    """
    entries = _ensure_registry()
    return {
        "count": len(entries),
        "entries": [_gna_to_dict(e) for e in entries],
    }


def get_gna_entry(
    id: int | None = None,
    short_name: str | None = None,
) -> dict:
    """Get a specific GNA entry by its numeric ID or exact short name.

    Exactly one of id or short_name must be provided.

    Args:
        id: The numeric GNA identifier (e.g. 3).
        short_name: The exact short name of the GNA (e.g. "CIRCL").

    Returns:
        The matching GNA entry or an error message if not found.
    """
    if id is None and short_name is None:
        raise ValueError("Provide either id or short_name")

    entries = _ensure_registry()

    if id is not None:
        result = get_gna(id, entries)
    else:
        result = get_gna_by_short_name(short_name, entries)

    if result is None:
        return {"error": "GNA entry not found", "id": id, "short_name": short_name}
    return _gna_to_dict(result)


def search_gna(query: str) -> dict:
    """Search for GNA entries by name (case-insensitive substring match).

    Args:
        query: Search term to match against GNA short names.

    Returns:
        A dict with count and matching GNA entries.
    """
    entries = _ensure_registry()
    matches = find_gna_by_short_name(query, entries)
    return {
        "query": query,
        "count": len(matches),
        "entries": [_gna_to_dict(e) for e in matches],
    }


def _ensure_cna_partners() -> list[CNAPartner]:
    """Download (if changed) and return the CNA partners list."""
    update_cna_partners()
    return load_cna_partners()


def _cna_summary(entry: CNAPartner) -> dict:
    """Trim a partner record to its identifying fields.

    The full dataset is over 600 KB, so list results leave out the metadata
    block; get_cna_partner returns it for a single partner.
    """
    return {
        "partner": entry.get("partner", ""),
        "short_name": entry.get("metadata", {}).get("short_name", ""),
        "country": entry.get("country", ""),
        "program_role": entry.get("program_role", ""),
        "organization_type": entry.get("organization_type", ""),
        "scope": entry.get("scope", ""),
    }


def search_cna_partners(
    name: str | None = None,
    country: str | None = None,
    program_role: str | None = None,
    organization_type: str | None = None,
) -> dict:
    """Search the CNA partners of the CVE Program.

    All filters are optional and combined with AND; with no filter, every
    partner is returned. Partners are CVE Numbering Authorities and related
    organizations as published on cve.org, mirrored at gcve.eu.

    Args:
        name: Case-insensitive substring match against the partner name or
            short name (e.g. "circl", "microsoft").
        country: Country name, case-insensitive exact match (e.g. "Luxembourg").
        program_role: Case-insensitive substring match against the program
            role (e.g. "CNA", "Root", "CNA-LR").
        organization_type: Case-insensitive substring match against the
            organization type (e.g. "Vendor", "CERT").

    Returns:
        A dict with the count and matching partners, each trimmed to:
        partner, short_name, country, program_role, organization_type, scope.
        Use get_cna_partner with a short_name for the full record.
    """
    partners = _ensure_cna_partners()

    if name:
        partners = find_cna_by_name(name.strip(), partners)
    if country:
        partners = get_cna_by_country(country.strip(), partners)
    if program_role:
        role = program_role.strip().lower()
        partners = [p for p in partners if role in p.get("program_role", "").lower()]
    if organization_type:
        org = organization_type.strip().lower()
        partners = [
            p for p in partners if org in p.get("organization_type", "").lower()
        ]

    return {
        "count": len(partners),
        "partners": [_cna_summary(p) for p in partners],
    }


def get_cna_partner(short_name: str) -> dict:
    """Get the full record of one CNA partner of the CVE Program.

    The short name is the CVE Program identifier for the partner — the same
    value that appears as assignerShortName in CVE records — so this tool can
    identify the authority behind a CVE returned by get_vulnerability.
    Use search_cna_partners to discover short names.

    Args:
        short_name: The partner's exact short name (e.g. "CIRCL", "microsoft").

    Returns:
        The full partner record, including metadata with cna_id, contacts,
        disclosure policy, security advisory links, and the root hierarchy —
        or an error message if not found.
    """
    partners = _ensure_cna_partners()
    result = get_cna_by_short_name(short_name.strip(), partners)
    if result is None:
        return {"error": "CNA partner not found", "short_name": short_name}
    return dict(result)


def list_gcve_references() -> dict:
    """List GCVE references (vulnerability dataset sources and their GNA mappings).

    This includes KEV catalog entries with their Vulnerability-Lookup
    origin UUIDs, which can be used with the list_kev_entries tool's
    vulnerability_lookup_origin parameter to query a specific catalog.

    Downloads references if not already cached locally.

    Returns:
        A dict with the reference categories and their entries, including
        KEV catalogs with uuid, short_name, and optional gna_id fields.
    """
    update_references()
    return load_references()


def register(mcp: FastMCP) -> None:
    """Register GCVE tools on the MCP server."""
    annotations = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    for tool in (
        list_gna_entries,
        get_gna_entry,
        search_gna,
        list_gcve_references,
        search_cna_partners,
        get_cna_partner,
    ):
        mcp.tool(annotations=annotations)(tool)
