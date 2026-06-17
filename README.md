<p align="center">
  <img src="docs/VulnMCP-logo.png" alt="VulnMCP logo" width="400">
</p>

# VulnMCP

**VulnMCP** is an [MCP](https://modelcontextprotocol.io/) server built with [FastMCP](https://gofastmcp.com/) that provides AI clients, chat agents, and other automated systems with tools for vulnerability management. It offers modular "skills" that can be easily extended or integrated, enabling intelligent analysis and automated insights on software vulnerabilities.

## Features

* **Vulnerability Severity Classification** -- Automatically assess the criticality of vulnerabilities using CIRCL's fine-tuned NLP models:
  [CIRCL/vulnerability-severity-classification-roberta-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-roberta-base) (English), [CIRCL/vulnerability-severity-classification-chinese-macbert-base](https://huggingface.co/CIRCL/vulnerability-severity-classification-chinese-macbert-base) (Chinese), and [CIRCL/vulnerability-severity-classification-russian-ruRoberta-large](https://huggingface.co/CIRCL/vulnerability-severity-classification-russian-ruRoberta-large) (Russian).
* **CWE Classification** -- Predict CWE categories from vulnerability descriptions using [CIRCL/cwe-parent-vulnerability-classification-roberta-base](https://huggingface.co/CIRCL/cwe-parent-vulnerability-classification-roberta-base).
* **Vulnerability Lookup** -- Query the [Vulnerability Lookup](https://vulnerability.circl.lu) API to get detailed information about specific CVEs, search vulnerabilities by source, CWE, product, or date, find community comments, and discover curated vulnerability bundles.
* **KEV Catalog** -- Browse and filter Known Exploited Vulnerability (KEV) entries, check whether a CVE appears in a KEV catalog, find recently added entries, and filter by catalog origin (CISA KEV, CIRCL, EUVD KEV).
* **GCVE Registry** -- Query the [GCVE](https://gcve.eu) Global Numbering Authority (GNA) registry and references to discover vulnerability allocators and KEV catalog identifiers.
* **Modular Architecture** -- Easily add new skills or tools to expand the functionality of the MCP server.

## Installation

Requires Python 3.10+ and [Poetry](https://python-poetry.org/) v2+.

```bash
git clone https://github.com/vulnerability-lookup/VulnMCP.git
cd VulnMCP
poetry install          # API tools only
poetry install -E ml    # includes ML classifiers (torch + transformers)
```

> **Note:** On Linux, `poetry install -E ml` resolves the default PyTorch wheel
> which includes CUDA libraries (~5 GB). To replace with CPU-only PyTorch
> after installation:
>
> ```bash
> poetry install -E ml
> poetry run pip install --force-reinstall "torch>=2.0.0,<3.0.0" --index-url https://download.pytorch.org/whl/cpu
> poetry run pip uninstall -y nvidia-cublas-cu12 nvidia-cuda-cupti-cu12 nvidia-cuda-nvrtc-cu12 nvidia-cuda-runtime-cu12 nvidia-cudnn-cu12 nvidia-cufft-cu12 nvidia-curand-cu12 nvidia-cusolver-cu12 nvidia-cusparse-cu12 nvidia-cusparselt-cu12 nvidia-nccl-cu12 nvidia-nvtx-cu12 nvidia-nvjitlink-cu12 nvidia-cufile-cu12 triton 2>/dev/null
> ```

### Docker

The Dockerfile accepts `INSTALL_ML` with three values:

| Value | Description | Image size |
|-------|-------------|------------|
| `false` (default) | API tools only, no torch/transformers | ~593 MB |
| `cpu` | ML classifiers with CPU-only PyTorch | ~1.6 GB |
| `gpu` | ML classifiers with CUDA-enabled PyTorch | ~5+ GB |

```bash
docker build -t vulnmcp .                                    # API only
docker build --build-arg INSTALL_ML=cpu -t vulnmcp:cpu .     # ML, CPU
docker build --build-arg INSTALL_ML=gpu -t vulnmcp:gpu .     # ML, GPU/CUDA
```

The `gpu` variant requires [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) and must be run with GPU access:

```bash
docker run --gpus all -p 9000:9000 vulnmcp:gpu
```

The `cpu` variant installs `torch` via pip from the PyTorch CPU index
rather than from `poetry.lock`, so ML dependency versions may differ
from the lockfile. The `gpu` variant uses `poetry install -E ml` and
is fully lockfile-pinned. Non-ML dependencies are always lockfile-pinned.

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
| `classify_severity` | *(requires `-E ml`)* Classify vulnerability severity (low/medium/high/critical) from a text description. Supports English, Chinese, and Russian with auto-detection. |
| `classify_cwe` | *(requires `-E ml`)* Predict CWE categories from a vulnerability description. Returns top-5 predictions with parent CWE mapping. |
| `get_recent_vulnerabilities_by_cwe` | Fetch the 3 most recent CVEs for a given CWE ID. |
| `get_vulnerability` | Look up a specific vulnerability by ID (e.g. CVE-2025-14847) with optional comments, sightings, bundles, linked vulnerabilities, and KEV enrichment. |
| `search_vulnerabilities` | Search vulnerabilities with filters: source, CWE, product, date range, pagination, and optional KEV-aware prioritization. |
| `search_sightings` | Search vulnerability sightings (seen/exploited/patched/etc.) with filters to identify what is actively discussed or abused. |
| `create_sighting` | Create a new sighting for a vulnerability (requires API permissions on most instances). |
| `get_most_sighted_vulnerabilities` | Retrieve a ranking of vulnerabilities by sighting activity to help prioritize important issues. |
| `search_comments` | Search community comments related to vulnerabilities, with filters by vulnerability ID or author. |
| `search_bundles` | Search curated vulnerability bundles (grouped CVEs for a campaign, product, or incident), with filters by vulnerability ID or author. |
| `list_kev_entries` | List and filter KEV catalog entries by vulnerability ID, status reason, exploited flag, date range, author, or origin catalog UUID. |
| `guess_cpes` | Query cpe-guesser with product keywords to infer likely CPE identifiers. |
| `list_gna_entries` | List all Global Numbering Authorities (GNA) from the GCVE registry. |
| `get_gna_entry` | Get a specific GNA entry by numeric ID or exact short name. |
| `search_gna` | Search GNA entries by name (case-insensitive substring match). |
| `list_gcve_references` | List GCVE references including KEV catalog UUIDs for use with `list_kev_entries`. |

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

# Search comments for a specific CVE
poetry run fastmcp call vulnmcp/server.py search_comments vuln_id=CVE-2024-3094

# Search bundles related to a CVE
poetry run fastmcp call vulnmcp/server.py search_bundles vuln_id=CVE-2024-3094

# Check if a CVE is in a KEV catalog
poetry run fastmcp call vulnmcp/server.py list_kev_entries vuln_id=CVE-2021-44228

# List recent KEV entries from the last week
poetry run fastmcp call vulnmcp/server.py list_kev_entries date_from=2026-03-18 per_page=5

# List KEV entries from the CISA KEV catalog only
poetry run fastmcp call vulnmcp/server.py list_kev_entries vulnerability_lookup_origin=405284c2-e461-4670-8979-7fd2c9755a60 per_page=5

# Guess likely CPE values from product keywords
poetry run fastmcp call vulnmcp/server.py guess_cpes query='["outlook","connector"]'

# List all GNA entries from the GCVE registry
poetry run fastmcp call vulnmcp/server.py list_gna_entries

# Look up a specific GNA by short name
poetry run fastmcp call vulnmcp/server.py get_gna_entry short_name=CIRCL

# Search GNA entries
poetry run fastmcp call vulnmcp/server.py search_gna query=cert

# List GCVE references (includes KEV catalog UUIDs)
poetry run fastmcp call vulnmcp/server.py list_gcve_references

# Classify severity from a description (requires -E ml)
poetry run fastmcp call vulnmcp/server.py classify_severity \
    description="A remote code execution vulnerability allows an attacker to execute arbitrary code via a crafted JNDI lookup."

# Classify CWE from a description (requires -E ml)
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
