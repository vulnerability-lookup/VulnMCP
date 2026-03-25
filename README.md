# VulnMCP

**VulnMCP** is an [MCP](https://modelcontextprotocol.io/) server built with [FastMCP](https://gofastmcp.com/) that provides AI clients, chat agents, and other automated systems with tools for vulnerability management. It offers modular "skills" that can be easily extended or integrated, enabling intelligent analysis and automated insights on software vulnerabilities.

## Features

* **Vulnerability Severity Classification** -- Automatically assess the criticality of vulnerabilities using CIRCL's fine-tuned NLP models:
  [CIRCL/vulnerability-severity-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base) (English) and [CIRCL/vulnerability-severity-classification-chinese-macbert-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base) (Chinese).
* **CWE Classification** -- Predict CWE categories from vulnerability descriptions using [CIRCL/cwe-parent-vulnerability-classification-roberta-base](https://huggingface.co/CIRCL/cwe-parent-vulnerability-classification-roberta-base).
* **Vulnerability Lookup** -- Query the [Vulnerability Lookup](https://vulnerability.circl.lu) API to get detailed information about specific CVEs or search vulnerabilities by source, CWE, product, or date.
* **KEV Catalog** -- Browse and filter Known Exploited Vulnerability (KEV) entries, check whether a CVE appears in a KEV catalog, and find recently added entries.
* **Modular Architecture** -- Easily add new skills or tools to expand the functionality of the MCP server.

## Installation

Requires Python 3.10+ and [Poetry](https://python-poetry.org/) v2+.

```bash
git clone https://github.com/vulnerability-lookup/VulnMCP.git
cd VulnMCP
poetry install
```

## Running the MCP server

### stdio (default)

The default transport, used by most MCP clients (Claude Code, Claude Desktop, etc.):

```bash
poetry run vulnmcp
```

### HTTP transport

For network access or multiple concurrent clients:

```bash
poetry run fastmcp run vulnmcp/server.py --transport http --host 127.0.0.1 --port 9000
```

## Available tools

| Tool | Description |
|------|-------------|
| `classify_severity` | Classify vulnerability severity (low/medium/high/critical) from a text description. Supports English and Chinese with auto-detection. |
| `classify_cwe` | Predict CWE categories from a vulnerability description. Returns top-5 predictions with parent CWE mapping. |
| `get_recent_vulnerabilities_by_cwe` | Fetch the 3 most recent CVEs for a given CWE ID. |
| `get_vulnerability` | Look up a specific vulnerability by ID (e.g. CVE-2025-14847) with optional comments, sightings, bundles, linked vulnerabilities, and KEV enrichment. |
| `search_vulnerabilities` | Search vulnerabilities with filters: source, CWE, product, date range, pagination, and optional KEV-aware prioritization. |
| `search_sightings` | Search vulnerability sightings (seen/exploited/patched/etc.) with filters to identify what is actively discussed or abused. |
| `create_sighting` | Create a new sighting for a vulnerability (requires API permissions on most instances). |
| `get_most_sighted_vulnerabilities` | Retrieve a ranking of vulnerabilities by sighting activity to help prioritize important issues. |
| `list_kev_entries` | List and filter KEV catalog entries by vulnerability ID, status reason, exploited flag, date range, or author. |
| `guess_cpes` | Query cpe-guesser with product keywords to infer likely CPE identifiers. |

List all tools:

```bash
poetry run fastmcp list vulnmcp/server.py
```

## Testing tools from the command line

Use `fastmcp call` to invoke any tool directly:

```bash
# Look up a specific CVE
poetry run fastmcp call vulnmcp/server.py get_vulnerability vulnerability_id=CVE-2025-14847

# Search for recent SQL injection vulnerabilities
poetry run fastmcp call vulnmcp/server.py search_vulnerabilities cwe=CWE-89 per_page=5

# Retrieve top most-sighted vulnerabilities
poetry run fastmcp call vulnmcp/server.py get_most_sighted_vulnerabilities limit=5

# Check if a CVE is in a KEV catalog
poetry run fastmcp call vulnmcp/server.py list_kev_entries vuln_id=CVE-2021-44228

# List recent KEV entries from the last week
poetry run fastmcp call vulnmcp/server.py list_kev_entries date_from=2026-03-18 per_page=5

# Guess likely CPE values from product keywords
poetry run fastmcp call vulnmcp/server.py guess_cpes query='["outlook","connector"]'

# Classify severity from a description
poetry run fastmcp call vulnmcp/server.py classify_severity \
    description="A remote code execution vulnerability allows an attacker to execute arbitrary code via a crafted JNDI lookup."

# Classify CWE from a description
poetry run fastmcp call vulnmcp/server.py classify_cwe \
    description="Fix buffer overflow in authentication handler"
```

## Connecting to Claude Code

Register VulnMCP as an MCP server in Claude Code with:

```bash
claude mcp add vulnmcp -- poetry --directory /path/to/VulnMCP run vulnmcp
```

Or with `fastmcp install`:

```bash
poetry run fastmcp install claude-code vulnmcp/server.py --name VulnMCP
```

Once registered, the tools are available to Claude Code. You can verify with:

```bash
claude mcp list
```

## Configuration

| Environment variable | Description | Default |
|---------------------|-------------|---------|
| `VULNMCP_LOOKUP_URL` | Base URL for the Vulnerability Lookup API | `https://vulnerability.circl.lu` |
| `VULNMCP_CPE_GUESSER_URL` | Base URL for the cpe-guesser API | `https://cpe-guesser.cve-search.org` |
| `VULNMCP_API_KEY` | API key used for authenticated actions such as creating sightings | _(unset)_ |

## Contributing

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request.

> Note: this repository currently runs an experiment where only computer-assisted (AI-related) contributions are accepted.

## License

[AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.html)
