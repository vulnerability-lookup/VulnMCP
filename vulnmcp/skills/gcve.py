from __future__ import annotations

from gcve.gna import GNAEntry, find_gna_by_short_name, get_gna, get_gna_by_short_name
from gcve.registry import (
    load_references,
    load_registry,
    update_references,
    update_registry,
    update_registry_public_key,
    update_registry_signature,
    verify_registry_integrity,
)
from fastmcp import FastMCP


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


def register(mcp: FastMCP) -> None:
    """Register GCVE tools on the MCP server."""

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )
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

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )
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

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )
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

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )
    def list_gcve_references() -> dict:
        """List GCVE references (vulnerability dataset sources and their GNA mappings).

        Downloads references if not already cached locally.

        Returns:
            A dict with the reference categories and their entries.
        """
        update_references()
        return load_references()
