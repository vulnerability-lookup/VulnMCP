# Changelog

All notable changes to VulnMCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.0.0] - 2026-08-30

### Added

- **ATT&CK technique classification** skill (`classify_attack_techniques`) predicting MITRE ATT&CK (Enterprise) techniques from vulnerability descriptions with CIRCL's fine-tuned multi-label RoBERTa model.
- **Russian severity classification** support in `classify_severity` using CIRCL's ruRoBERTa-large model, with automatic language detection alongside English and Chinese.
- `search_comments` and `search_bundles` tools to find community comments and curated vulnerability bundles.
- **CNA partners** tools in the GCVE skill, using the CNA partners support added in gcve 0.13.0:
  - `search_cna_partners` -- search the CNA partners of the CVE Program by name, country, program role, or organization type.
  - `get_cna_partner` -- get one partner's full record (disclosure policy, security advisory links, contacts, root hierarchy) by exact short name.
- Offline pytest test suite and a GitHub Actions workflow running it on Python 3.10 and 3.13.
- `prompts/` directory with a prompt for generating monthly vulnerability reports.

### Changed

- Extracted the shared Vulnerability Lookup HTTP layer into `vulnmcp/lookup.py`; MCP tools are now plain module-level functions registered by each skill's `register()`.
- `transformers` (and torch) are imported lazily, cutting package import time to well under a second.
- Sighting and comment/bundle tools use the PyVulnerabilityLookup client.
- CPU-only torch is installed by default; CUDA builds are opt-in via `poetry install --extras cuda`.
- Upgraded to transformers 5.x.
- `get_recent_vulnerabilities_by_cwe` now prefers English descriptions when a record carries several languages.

### Removed

- The Dockerfile.

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
