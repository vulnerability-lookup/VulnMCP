# Changelog

All notable changes to VulnMCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-03-26

### Added

- MCP server built with FastMCP, supporting stdio and HTTP transports.
- **Severity classification** skill using CIRCL's fine-tuned transformer models for English and Chinese vulnerability descriptions.
- **CWE classification** skill to predict CWE categories from vulnerability descriptions, with parent CWE hierarchy mapping.
- **Vulnerability Lookup** skill to query the Vulnerability Lookup API:
  - `get_vulnerability` -- look up a specific vulnerability by ID with optional comments, sightings, bundles, linked vulnerabilities, and KEV enrichment.
  - `search_vulnerabilities` -- search vulnerabilities by source, CWE, product, date range, with optional KEV-aware prioritization.
  - `guess_cpes` -- infer likely CPE identifiers from product keywords via cpe-guesser.
- **Sighting tools** for vulnerability prioritization:
  - `search_sightings` -- search sightings by vulnerability, type, source, author, or date range.
  - `create_sighting` -- create a new sighting for a vulnerability (requires API key).
  - `get_most_sighted_vulnerabilities` -- rank vulnerabilities by sighting activity.
- **KEV catalog** support:
  - `list_kev_entries` -- browse and filter Known Exploited Vulnerability entries by vulnerability ID, status reason, exploited flag, date range, author, or origin catalog UUID.
  - KEV enrichment integrated into `get_vulnerability` and `search_vulnerabilities`.
- **GCVE registry** skill using the [gcve](https://pypi.org/project/gcve/) library:
  - `list_gna_entries` -- list all Global Numbering Authorities from the GCVE registry.
  - `get_gna_entry` -- look up a specific GNA by numeric ID or short name.
  - `search_gna` -- search GNA entries by name (case-insensitive substring match).
  - `list_gcve_references` -- list GCVE references including KEV catalog UUIDs.
- MCP tool annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) on all tools.
- Custom `User-Agent` header on all Vulnerability Lookup API requests.
- Configurable base URLs via `VULNMCP_LOOKUP_URL`, `VULNMCP_CPE_GUESSER_URL`, and API key via `VULNMCP_API_KEY`.
